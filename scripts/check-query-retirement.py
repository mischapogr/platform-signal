#!/usr/bin/env python3
"""Owned monolith/S3 retirement-recovery simulation; no cloud or deletion proof.

Uses an explicitly synthetic, authenticated-chain-bound retirement control to
exercise the server's query and WAL rollback guard. Rust acceptance separately
qualifies production retirement publication and interrupted-control recovery.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import struct
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('signal_object_query_fixture', ROOT / 'scripts/check-object-query.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)


def replace_bytes(path, data):
    if not 0 < len(data) <= 4096:
        raise RuntimeError('bounded control bytes required')
    temporary = path.with_suffix('.fixture-tmp')
    with temporary.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Run(BASE.Run):
    def __init__(self, output, binary):
        super().__init__(output, binary)
        self.replay = output / 'wal-replay-witnesses'
        self.replay.mkdir()

    def stop(self, name, kill=False):
        if name == 'server' and kill:
            # Capture actual synced admission records at the base run's existing
            # crash milestones, before ACK/reclamation. Never fabricate WAL rows.
            paths = list((self.server_root / 'wal').glob('*.wal'))
            if len(paths) > 2:
                raise RuntimeError('bounded replay witness inventory')
            for path in paths:
                if path.is_symlink() or not path.is_file() or path.name not in ['00000000000000000003.wal', '00000000000000000004.wal']:
                    raise RuntimeError('unexpected replay witness')
                with path.open('rb') as stream:
                    data = stream.read(4097)
                if not 20 <= len(data) <= 4096 or data[:8] != b'SIGWAL01' or zlib.crc32(data[:16]) != struct.unpack('<I', data[16:20])[0]:
                    raise RuntimeError('bounded synced WAL segment witness required')
                replace_bytes(self.replay / path.name, data)
        return super().stop(name, kill)

    def restore_replay(self):
        paths = list(self.replay.glob('*.wal'))
        if {path.name for path in paths} != {'00000000000000000003.wal', '00000000000000000004.wal'}:
            raise RuntimeError('both actual retained admission witnesses required')
        for path in paths:
            replace_bytes(self.server_root / 'wal' / path.name, path.read_bytes())

    def finding_ids(self):
        findings = super().finding_ids()
        self.last_findings = findings
        return findings

    def run(self):
        canonical = super().run()
        findings = self.last_findings
        if len(findings) != 4:
            raise RuntimeError('exact baseline finding history required')
        catalog = BASE.read_json(self.fixture_root / 'catalog.json')
        bodies = {meta['file']: BASE.file_hash(self.fixture_root / 'objects' / meta['file']) for meta in catalog.values()}
        control = self.server_root / 'control'
        head_bytes = (control / 'head.json').read_bytes()
        head = json.loads(head_bytes)
        binding = BASE.read_json(control / 'binding.json', 256)
        checkpoint_path = self.server_root / 'wal/checkpoint'
        checkpoint_bytes = checkpoint_path.read_bytes()
        if self.checkpoint() != 4 or head['current']['last_sequence'] != 4 or head['previous']['last_sequence'] != 3:
            raise RuntimeError('exact stopped checkpoint and committed anchor required')
        # This is a fixture, not an operator deletion or checkpoint capability.
        record = {
            'schema_version': 1, 'stream_id': binding['stream_id'], 'backend_id': binding['backend_id'],
            'previous_anchor': None, 'anchor': head['previous'], 'wal_checkpoint': 4,
            'assessed_at': '2026-07-10T23:00:00Z', 'query_before': '2026-07-10T22:00:00Z',
            'policy': {'schema_version': 1, 'raw_seconds': None, 'query_seconds': 3600,
                       'index_seconds': None, 'replay_seconds': 1800, 'evidence_reference_seconds': 7200,
                       'reader_seconds': 600, 'orphan_grace_seconds': 1800},
        }
        encoded = json.dumps(record, separators=(',', ':')).encode()
        replace_bytes(control / 'retirement.tmp', encoded)
        self.start_fixture()
        self.start_server()
        visible = self.events()
        expected = [event for event in canonical['events'] if event['timestamp'] == '2026-07-10T22:00:00Z']
        if len(expected) != 1 or visible['events'] != expected or visible['metadata']['scanned_files'] != 1:
            raise RuntimeError('retired prefix remained queryable or changed live event')
        if self.checkpoint() != 4 or self.finding_ids() != findings:
            raise RuntimeError('retirement changed WAL checkpoint or finding history')
        if (control / 'retirement.json').read_bytes() != encoded or (control / 'retirement.tmp').exists():
            raise RuntimeError('pending retirement not authenticated and recovered')
        self.record('synthetic_retirement_control_authenticated_at_real_server_startup',
                    retired_through=3, checkpoint=4, visible_event_ids=[event['id'] for event in expected],
                    scanned_files=1, finding_count=4, control_scope='synthetic chain-bound fixture')
        self.stop('server')
        # Restore actual synced WAL admissions captured before the base run's
        # crash/ACK milestones. A reclaimed WAL plus checkpoint rollback alone
        # would also fail the older high-water guard and prove no new behavior.
        rolled = bytearray(checkpoint_bytes)
        struct.pack_into('<Q', rolled, 8, 2)
        struct.pack_into('<I', rolled, 24, zlib.crc32(rolled[:24]))
        replace_bytes(checkpoint_path, rolled)
        self.restore_replay()
        # Negative control: prove the previous frontier checks permit this exact
        # WAL/store state when the synthetic retirement witness is absent. Replay
        # must retain the four canonical identities without extra remote objects.
        held = self.out / 'retirement-held.json'
        os.rename(control / 'retirement.json', held)
        self.start_server()
        if self.stable_events([event['id'] for event in canonical['events']])['events'] != canonical['events']:
            raise RuntimeError('negative frontier control changed canonical events')
        self.wait(lambda: self.checkpoint() == 4)
        if self.finding_ids() != findings:
            raise RuntimeError('negative frontier control changed finding history')
        self.stop('server')
        os.rename(held, control / 'retirement.json')
        replace_bytes(checkpoint_path, rolled)
        self.restore_replay()
        self.record('rollback_without_retirement_passes_existing_frontier_checks',
                    rolled_checkpoint=2, restored_checkpoint=4, canonical_event_count=4,
                    replay_witness_sha256={path.name: BASE.file_hash(path) for path in self.replay.glob('*.wal')})
        self.server = self.spawn([str(self.binary)], self.env(), 'server-retirement-rollback')
        code = self.server.wait(timeout=12)
        child = self.server
        self.reap_log(child)
        self.reaped(child)
        self.server = None
        if code == 0 or b'storage high water and WAL checkpoint are incompatible' not in self.logs[-1].read_bytes():
            raise RuntimeError('rollback below retirement did not fail closed at frontier guard')
        if checkpoint_path.read_bytes() != rolled or (control / 'head.json').read_bytes() != head_bytes or (control / 'retirement.json').read_bytes() != encoded:
            raise RuntimeError('rejected restore changed control or checkpoint')
        self.record('real_server_rejects_wal_checkpoint_below_retired_floor',
                    retired_through=3, rolled_checkpoint=2, exit_code=code)
        replace_bytes(checkpoint_path, checkpoint_bytes)
        self.start_server()
        if self.events()['events'] != expected or self.checkpoint() != 4 or self.finding_ids() != findings:
            raise RuntimeError('consistent checkpoint restore did not recover live query')
        self.stop('server')
        self.stop('fixture')
        if BASE.read_json(self.fixture_root / 'catalog.json') != catalog or any(BASE.file_hash(self.fixture_root / 'objects' / name) != digest for name, digest in bodies.items()):
            raise RuntimeError('logical retirement mutated remote object inventory')
        for path in self.logs:
            if any(secret.encode() in path.read_bytes() for secret in [BASE.TOKEN, 'synthetic-query-access', 'synthetic-query-secret', 'synthetic-query-session']):
                raise RuntimeError('secret sentinel in retirement process log')
        self.record('consistent_wal_restore_recovers_without_remote_reclamation',
                    checkpoint=4, visible_event_ids=[event['id'] for event in expected], remote_objects=len(catalog))
        return canonical


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    output, binary = args.output.absolute(), args.binary.absolute()
    if output.exists() or binary.is_symlink() or not binary.is_file():
        raise RuntimeError('fresh owned output and immutable binary required')
    output.mkdir(parents=True)
    run = Run(output, binary)
    started = time.monotonic()
    report = {'schema_version': 1, 'status': 'in_progress', 'full_release': False,
              'scope': 'Owned monolith/S3 simulation with synthetic chain-bound retirement control; no deletion',
              'binary_sha256': BASE.file_hash(binary)}
    try:
        canonical = run.run()
        report.update(status='passed_simulated', scenarios=run.scenarios, canonical_event_count=len(canonical['events']))
    except BaseException as error:
        report.update(status='failed', scenarios=run.scenarios, error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        errors = run.cleanup()
        if errors:
            report.update(status='failed', cleanup_errors=errors)
        report.update(processes=run.processes, elapsed_seconds=round(time.monotonic() - started, 3),
                      external_exceptions=['AWS/IAM/KMS/Object Lock/TLS runtime', 'native ARM64/EKS/shared HA', 'custody/completeness'],
                      logs={str(path.relative_to(output)): BASE.file_hash(path) for path in run.logs if path.exists()})
        BASE.write_json(output / 'report.json', report)
    print(json.dumps(report, indent=2))
    if report['status'] != 'passed_simulated':
        raise RuntimeError('simulation cleanup failed; retained report')


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise KeyboardInterrupt('owned simulation interrupted by signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    main()

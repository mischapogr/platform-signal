#!/usr/bin/env python3
"""Actual agent/spool/uncertain-HTTP/restart proof using retained local kind originals."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('audit_agent_pipeline', ROOT / 'scripts/check-security-requirements.py')
PIPE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PIPE)
require = PIPE.require
SOURCE_PATHS = ['apps/signal-agent/src/' + name + '.rs' for name in
                ['config', 'contracts', 'input', 'runtime', 'spool', 'main', 'http']]
SOURCE_PATHS += ['scripts/check-kubernetes-audit-agent.py', 'scripts/test-kubernetes-audit-agent.py', 'scripts/check-security-requirements.py',
                 'crates/signal-collector-sdk/src/kubernetes_audit.rs', 'Cargo.lock',
                 'tests/fixtures/security-requirements/catalog.json']


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def source_hashes():
    return {name: digest(ROOT / name) for name in SOURCE_PATHS}


def frame(path):
    require(path.stat().st_size <= 128 * 1024, 'bounded spool frame')
    raw = path.read_bytes()
    require(len(raw) >= 12 and len(raw) == 12 + int.from_bytes(raw[:4], 'little'), 'frame length')
    require(zlib.crc32(raw[:8]) == int.from_bytes(raw[8:12], 'little'), 'frame header CRC')
    require(zlib.crc32(raw[12:]) == int.from_bytes(raw[4:8], 'little'), 'frame payload CRC')
    return json.loads(raw[12:])


def wal_checkpoint(path):
    raw = path.read_bytes()
    require(len(raw) == 28 and raw[:8] == b'SIGACK01', 'WAL checkpoint schema')
    require(zlib.crc32(raw[:24]) == int.from_bytes(raw[24:], 'little'), 'WAL checkpoint CRC')
    require(int.from_bytes(raw[16:24], 'little') == 0, 'zero WAL drops')
    return int.from_bytes(raw[8:16], 'little')


def records(spool):
    paths = sorted(spool.glob('record-*'))
    require(len(paths) <= 16, 'fixture record count')
    return [frame(path)['event'] for path in paths]


def wait(check, label, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.025)
    raise ValueError('deadline: ' + label)


def run(args):
    output = args.output.resolve()
    require(output.is_relative_to((ROOT / 'target').resolve()), 'output under target')
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    began = time.monotonic()
    before = source_hashes()
    capture = args.capture.resolve()
    capture_report = json.loads((capture / 'report.json').read_text())
    require(capture_report['status'] == 'passed_local' and capture_report['owned_cleanup'], 'accepted prior kind capture')
    require(digest(capture / 'audit.log') == capture_report['capture_sha256'], 'retained exact original capture')
    document = json.loads((capture / 'capture.json').read_text())
    require(len(document['cases']) == 6 and document['policy_revision'] == capture_report['policy_sha256'], 'capture policy and cases')
    native = [case['raw_utf8'] for case in document['cases']]
    original_lines = (capture / 'audit.log').read_text().splitlines()
    require(all(line in original_lines for line in native), 'selected exact native lines')
    source = output / 'audit.jsonl'
    source.write_text('\n'.join(native) + '\nmalformed\n' + 'x' * 65537 + '\n')
    initial_bytes = source.stat().st_size
    spool = output / 'agent-spool'
    (output / 'rules').mkdir()
    catalog = json.loads((ROOT / 'tests/fixtures/security-requirements/catalog.json').read_text())
    rule = next(d['native_rule'] for d in catalog['detections'] if d['id'] == 'SIG-D07')
    (output / 'rules/D07.yaml').write_text(json.dumps(rule))
    server, address = None, None
    proxy, thread = None, None
    release = threading.Event()
    forwarded = threading.Event()
    calls = []
    processes = []
    report = {'schema_version': 1, 'status': 'failed', 'source_sha256': before,
              'scope': 'production agent file mode, retained local kind originals, actual Small HTTP/WAL/findings',
              'limits': ['local AMD64; no AWS/EKS/current ARM64/CI', 'no global audit-ID deduplication or complete source coverage']}

    class Proxy(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def log_message(self, *unused):
            pass

        def do_POST(self):
            require(self.path == '/v1/events/batch', 'proxy route')
            length = int(self.headers.get('Content-Length', '0'))
            require(0 < length <= 128 * 1024, 'proxy body limit')
            require(self.headers.get('Authorization') == 'Bearer ' + PIPE.TOKEN, 'agent authentication')
            body = json.loads(self.rfile.read(length))
            require(len(body['events']) == 1 and len(calls) < 16, 'one-event bounded requests')
            calls.append(body['events'][0])
            status, ack = PIPE.request(address, 'POST', self.path, body)
            require(status == 202, 'actual server admitted')
            if len(calls) == 1:
                forwarded.set()
                require(release.wait(timeout=15), 'lost response handoff deadline')
                self.close_connection = True
                return  # Successful server ACK is intentionally never returned.
            raw = json.dumps(ack).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    env = {key: value for key, value in os.environ.items() if not key.startswith('SIGNAL_')}
    env['SIGNAL_AGENT_API_TOKEN'] = PIPE.TOKEN
    common = ['--file', str(source),
              '--spool-dir', str(spool), '--batch-events', '1', '--flush-ms', '1',
              '--request-timeout-ms', '10000', '--shutdown-timeout-ms', '10000']
    profile = ['--format', 'kubernetes-audit-json', '--source-name', document['cluster'],
               '--audit-policy-sha256', document['policy_revision']]

    def start(name, profile_args, once=False):
        with (output / (name + '.log')).open('xb') as log:
            process = subprocess.Popen([str(args.agent.resolve()), '--server', f'http://127.0.0.1:{proxy.server_port}', *common, *profile_args,
                                        *(['--once'] if once else [])], env=env, cwd=ROOT,
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        processes.append(process)
        return process

    try:
        server, address = PIPE.start(args.server.resolve(), output, 1)
        proxy = HTTPServer(('127.0.0.1', 0), Proxy)
        proxy.timeout = 0.1
        thread = threading.Thread(target=proxy.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        agent = start('agent-original', profile)
        wait(forwarded.is_set, 'first admitted request held without ACK')
        def admitted_all():
            state_path = spool / 'state'
            if not state_path.exists():
                return False
            cursors = frame(state_path)['cursors']
            return len(cursors) == 1 and cursors[0]['offset'] == initial_bytes and len(records(spool)) == 6
        wait(admitted_all, 'all native records and both rejected lines durably handled')
        pending = records(spool)
        projection = json.loads((capture / 'projection.json').read_text())['cases']
        require(len(projection) == len(pending), 'original native projection inventory')
        for event, projected in zip(pending, projection, strict=True):
            without_pins = lambda value: {key: val for key, val in value.items() if key not in {'id', 'observed_at'}}
            require(without_pins(event) == without_pins(projected['event']), 'actual native projected fields')
        original_findings = []
        def initial_persisted():
            nonlocal original_findings
            rows, findings = PIPE.snapshot(address)
            if len(rows) == 1 and len(findings) == 1 and wal_checkpoint(output / 'wal/checkpoint') == 1:
                require(rows[0] == pending[0] and findings[0]['event_ids'] == [pending[0]['id']], 'original persisted event/finding')
                original_findings = findings
                return True
            return False
        wait(initial_persisted, 'original D07 finding persisted before crash')
        cursor = frame(spool / 'state')['cursors'][0]
        require(len(cursor['source_binding']) == 64 and pending[0] == calls[0], 'original durable pins and source binding')
        agent.kill()
        require(agent.wait(timeout=5) == -signal.SIGKILL, 'actual agent SIGKILL before ACK')
        release.set()
        expected_pending = json.dumps(pending, sort_keys=True)
        for name, changed in [('cluster', profile[:3] + [document['cluster'] + '-changed'] + profile[4:]),
                              ('policy', profile[:-1] + ['0' * 64]),
                              ('mode', ['--format', 'json'])]:
            attempt = start('refused-' + name, changed, once=True)
            require(attempt.wait(timeout=8) != 0, 'profile drift refuses')
            require(len(calls) == 1 and json.dumps(records(spool), sort_keys=True) == expected_pending,
                    'profile refusal before any backlog send or payload replacement')
        # New input is appended after the persisted rejection cursor. It must be
        # sequenced behind all six original pending canonical records.
        with source.open('a') as destination:
            destination.write(native[1] + '\n')
        restarted = start('agent-restarted', profile, once=True)
        require(restarted.wait(timeout=20) == 0, 'original spool drains after restart')
        require(len(calls) == 8, 'one uncertain request plus seven drained records')
        require(calls[1:7] == pending, 'exact original canonical replay and backlog ordering')
        require(calls[7]['id'] not in {event['id'] for event in pending}, 'new source position has fresh pin')
        expected = {event['id']: event for event in [*pending, calls[7]]}
        rows, findings = [], []
        def final_persisted():
            nonlocal rows, findings
            rows, findings = PIPE.snapshot(address)
            return len(rows) == 8 and len(findings) == 1 and wal_checkpoint(output / 'wal/checkpoint') == 8
        wait(final_persisted, 'server persistence and zero-drop WAL checkpoint8')
        require(findings == original_findings, 'complete original finding bytes survive uncertain replay')
        require(len(rows) == 8 and {event['id'] for event in rows} == set(expected), 'at-least-once event rows')
        require(all(event == expected[event['id']] for event in rows), 'stored canonical bytes equal original pins')
        require(len(findings) == 1 and findings[0]['rule_id'] == 'SIG-D07'
                and findings[0]['event_ids'] == [pending[0]['id']], 'one original deterministic D07 finding')
        require(not records(spool), 'no pending spool records after drain')
        final_cursor = frame(spool / 'state')['cursors'][0]
        require(final_cursor['offset'] == source.stat().st_size and final_cursor['source_binding'] == cursor['source_binding'], 'original bound cursor advances')
        count = len(calls)
        resumed = start('agent-resumed-empty', profile, once=True)
        require(resumed.wait(timeout=10) == 0 and len(calls) == count, 'restart resumes exact source cursor without reread')
        report.update(original_pending=6, malformed_and_oversized_rejections=2,
                      actual_agent_sigkill=True, withheld_successful_response=True,
                      profile_refusals=3, canonical_replay_and_ordering=True,
                      persisted_event_rows=len(rows), unique_events=len(expected), findings=1,
                      wal_checkpoint=wal_checkpoint(output / 'wal/checkpoint'), original_finding_bytes_preserved=True,
                      source_cursor_offset=final_cursor['offset'], source_binding=final_cursor['source_binding'],
                      capture_sha256=capture_report['capture_sha256'], policy_sha256=document['policy_revision'],
                      agent_sha256=digest(args.agent), server_sha256=digest(args.server))
        require(before == source_hashes(), 'source drift during process campaign')
        report['status'] = 'passed_local'
    except BaseException:
        report['status'] = 'failed'
        raise
    finally:
        release.set()
        cleanup_ok = True
        for process in processes:
            try:
                PIPE.stop(process)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_ok = False
        if thread is not None and thread.is_alive():
            proxy.shutdown()
            thread.join(timeout=2)
        if proxy is not None:
            proxy.server_close()
        if server is not None:
            try:
                PIPE.stop(server)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_ok = False
        report['owned_cleanup'] = cleanup_ok and all(process.poll() is not None for process in [server, *processes] if process is not None) and (thread is None or not thread.is_alive())
        if not report['owned_cleanup']:
            report['status'] = 'failed'
        report['elapsed_seconds'] = round(time.monotonic() - began, 3)
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    require(report['status'] == 'passed_local', 'process campaign failed')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', required=True, type=Path)
    parser.add_argument('--server', required=True, type=Path)
    parser.add_argument('--capture', type=Path, default=ROOT / 'target/kubernetes-audit-capture-20261024/capture-01')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = run(args)
    print(json.dumps({'status': report['status'], 'report': str(args.output / 'report.json')}))


if __name__ == '__main__':
    main()

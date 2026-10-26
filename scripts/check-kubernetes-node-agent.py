#!/usr/bin/env python3
"""Production node agent/Small WAL/recovery qualification with owned synthetic CRI files."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('node_pipeline', ROOT / 'scripts/check-security-requirements.py')
PIPE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PIPE)
require = PIPE.require
SOURCE_PATHS = ['apps/signal-agent/src/' + x for x in ['config.rs', 'contracts.rs', 'input.rs', 'runtime.rs', 'spool.rs', 'main.rs', 'http.rs', 'node_root.rs', 'node_input.rs', 'node_input/state.rs']]
SOURCE_PATHS += ['apps/signal-agent/Cargo.toml', 'Cargo.lock', 'crates/signal-collector-sdk/src/kubernetes_log.rs', 'scripts/check-kubernetes-node-agent.py', 'scripts/check-security-requirements.py']


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def hashes():
    return {p: digest(ROOT / p) for p in SOURCE_PATHS}


def frame(path):
    require(path.stat().st_size <= 1024*1024, 'spool frame bound')
    raw = path.read_bytes()
    require(len(raw) >= 12 and len(raw) == 12 + int.from_bytes(raw[:4], 'little'), 'spool frame length')
    require(zlib.crc32(raw[:8]) == int.from_bytes(raw[8:12], 'little'), 'spool header CRC')
    require(zlib.crc32(raw[12:]) == int.from_bytes(raw[4:8], 'little'), 'spool payload CRC')
    return json.loads(raw[12:])


def records(spool):
    files = sorted(spool.glob('record-*'))
    require(len(files) <= 32, 'fixture pending record count')
    return [frame(p) for p in files]


def checkpoint(path):
    raw = path.read_bytes()
    require(len(raw) == 28 and raw[:8] == b'SIGACK01', 'server checkpoint format')
    require(zlib.crc32(raw[:24]) == int.from_bytes(raw[24:], 'little'), 'server checkpoint CRC')
    require(int.from_bytes(raw[16:24], 'little') == 0, 'zero WAL drops')
    return int.from_bytes(raw[8:16], 'little')


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


def native(message, stream='stdout', tag='F'):
    return b'2026-10-25T12:00:00Z ' + stream.encode() + b' ' + tag.encode() + b' ' + message + b'\n'


def cleanup_owned(processes, proxy, thread, server):
    errors = []
    actions = [*[lambda p=p: PIPE.stop(p) for p in processes],
               *([proxy.shutdown, proxy.server_close] if proxy is not None else []),
               *([lambda: thread.join(timeout=2)] if thread is not None else []),
               *([lambda: PIPE.stop(server)] if server is not None else [])]
    for action in actions:
        try:
            action()
        except BaseException as error:
            errors.append(type(error).__name__)
    if thread is not None and thread.is_alive():
        errors.append('ProxyThreadStillAlive')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', required=True, type=Path)
    parser.add_argument('--server', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.is_relative_to((ROOT / 'target').resolve()), 'owned output under target')
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    before = hashes()
    began = time.monotonic()
    root = output / 'pods'
    a = root / 'team_workload_runtime-a/main/0.log'
    z = root / 'team_workload_runtime-z/main/0.log'
    for path in [a, z]:
        path.parent.mkdir(parents=True)
    a.write_bytes(native(b'a-one') + native(b'a-two'))
    z.write_bytes(native(b'prefix', tag='P') + native(b'stderr\r', stream='stderr') + native(b'\xf0\x9f', tag='P') + native(b'\x98\x80') + b'malformed\n' + b'x'*65537 + b'\n')
    spool = output / 'spool'
    (output / 'rules').mkdir()
    server = proxy = thread = None
    processes = []
    calls = []
    forwarded = threading.Event()
    release = threading.Event()
    hold = {'at': 1}
    report = {'schema_version': 1, 'status': 'failed', 'source_sha256': before,
              'scope': 'production node worker/CLI/spool/actual Small HTTP,WAL,Parquet; synthetic rooted CRI files',
              'limits': ['local AMD64; not actual Kubernetes hostPath proof', 'gap events indicate uncertainty, not complete coverage', 'no AWS/EKS,current ARM64/CI or release qualification']}

    class Proxy(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def log_message(self, *unused):
            pass

        def do_POST(self):
            require(self.path == '/v1/events/batch', 'owned proxy route')
            length = int(self.headers.get('Content-Length', '0'))
            require(0 < length <= 1024*1024, 'bounded node HTTP body')
            require(self.headers.get('Authorization') == 'Bearer ' + PIPE.TOKEN, 'explicit agent authentication')
            body = json.loads(self.rfile.read(length))
            require(len(body['events']) == 1 and len(calls) < 64, 'bounded one-event fixture')
            calls.append(body['events'][0])
            status, ack = PIPE.request(address, 'POST', self.path, body)
            require(status == 202, 'actual Small WAL admission')
            if len(calls) == hold['at']:
                forwarded.set()
                require(release.wait(timeout=25), 'owned withheld-ACK deadline')
                self.close_connection = True
                return
            raw = json.dumps(ack).encode()
            self.send_response(status)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    env = {k: v for k, v in os.environ.items() if not k.startswith('SIGNAL_')}
    env['SIGNAL_AGENT_API_TOKEN'] = PIPE.TOKEN
    common = ['--spool-dir', str(spool), '--batch-events', '1', '--flush-ms', '1', '--request-timeout-ms', '20000', '--shutdown-timeout-ms', '10000']
    profile = ['--format', 'kubernetes-cri', '--node-log-root', str(root), '--node-name', 'node-a', '--node-namespace', 'team', '--source-name', 'cluster']

    def start(name, options=None, once=False):
        with (output / (name + '.log')).open('xb') as log:
            process = subprocess.Popen([str(args.agent.resolve()), '--server', 'http://127.0.0.1:' + str(proxy.server_port), *common, *(profile if options is None else options), *(['--once'] if once else [])], cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        processes.append(process)
        return process

    def persisted(count):
        rows, findings = PIPE.snapshot(address)
        return len(rows) == count and not findings and checkpoint(output / 'wal/checkpoint') == count

    def replace_option(option, value):
        changed = profile.copy()
        changed[changed.index(option)+1] = value
        return changed

    try:
        server, address = PIPE.start(args.server.resolve(), output, 1)
        proxy = HTTPServer(('127.0.0.1', 0), Proxy)
        thread = threading.Thread(target=proxy.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        first = start('agent-original')
        require(forwarded.wait(timeout=12), 'actual first admission withheld')
        def first_ready():
            state = frame(spool / 'state')
            return len(records(spool)) == 6 and state['version'] == 2 and len(state['cursors']) == 2 and all(c['offset'] == (a if c['source_identity']['source']['runtime_pod_uid'] == 'runtime-a' else z).stat().st_size for c in state['cursors'])
        wait(first_ready, 'six originals and two durable rejected-line positions')
        pending = [r['event'] for r in records(spool)]
        require(calls == pending[:1], 'only first prefix sent before lost ACK')
        require(any(e['attributes']['log']['tag'] == 'P' for e in pending), 'physical partial tag')
        require(any(e.get('message') == 'stderr\r' for e in pending), 'CR and stderr preserved')
        require(sum(e['attributes']['log']['payload_encoding'] == 'base64' for e in pending) == 2, 'split UTF8 lossless records')
        first.kill()
        require(first.wait(timeout=5) != 0, 'actual agent SIGKILL')
        release.set()
        wait(lambda: persisted(1), 'original first WAL row persisted')
        old = json.dumps(records(spool), sort_keys=True)
        other_root = output / 'foreign-root'
        other_root.mkdir()
        refusals = [replace_option('--source-name', 'other-cluster'), replace_option('--node-name', 'other-node'), replace_option('--node-namespace', 'other'), replace_option('--node-log-root', str(other_root)), profile + ['--max-line-bytes', '32768'], ['--format', 'json', '--file', str(z)]]
        for index, changed in enumerate(refusals):
            attempt = start('refused-' + str(index), changed, once=True)
            require(attempt.wait(timeout=8) != 0, 'profile drift refused')
            require(len(calls) == 1 and json.dumps(records(spool), sort_keys=True) == old, 'refusal before send or pending replacement')
        with z.open('ab') as file:
            file.write(native(b'after-first-restart'))
        restarted = start('agent-first-restart', once=True)
        require(restarted.wait(timeout=20) == 0, 'original node source resumes and drains')
        require(calls[1:7] == pending and len(calls) == 8, 'exact original six-event replay and new suffix')
        wait(lambda: persisted(8), 'first replay publication and WAL checkpoint')
        resumed = start('agent-empty-restart', once=True)
        require(resumed.wait(timeout=10) == 0 and len(calls) == 8, 'empty restart does not reread files')

        # Hold another successful response while generation gaps and slot reuse
        # are admitted behind that original event. Kill and replay all originals.
        hold['at'] = len(calls)+1
        release.clear()
        forwarded.clear()
        live = start('agent-generation-churn')
        with z.open('ab') as file:
            file.write(native(b'growth-after-eof'))
        require(forwarded.wait(timeout=12), 'second actual success withheld')
        rotated = z.with_name('0.log.rotation')
        z.rename(rotated)
        with rotated.open('ab') as file:
            file.write(native(b'old-rotated-tail'))
        z.write_bytes(native(b'new-generation'))
        shutil.rmtree(a.parents[1])
        new = root / 'team_workload_runtime-new/main/0.log'
        new.parent.mkdir(parents=True)
        new.write_bytes(native(b'new-pod-generation'))
        wait(lambda: len(records(spool)) == 6, 'generation data,gaps and replacement while ACK withheld')
        pending_again = [r['event'] for r in records(spool)]
        reasons = [e['attributes'].get('collection', {}).get('reason') for e in pending_again if e['source']['type'] == 'kubernetes.collector']
        require(sorted(reasons) == ['missing_generation', 'rotation_observed'], 'explicit durable collector gap events')
        require(any(e['attributes']['kubernetes']['pod']['runtime_uid'] == 'runtime-new' for e in pending_again), 'slot reused before old pending events acknowledged')
        live.kill()
        require(live.wait(timeout=5) != 0, 'second actual SIGKILL')
        release.set()
        with new.open('ab') as file:
            file.write(native(b'after-second-restart'))
        final = start('agent-second-restart', once=True)
        require(final.wait(timeout=20) == 0, 'reused registry restores and drains')
        require(calls[9:15] == pending_again and len(calls) == 16, 'exact gap/data replay across slot reuse')
        wait(lambda: persisted(16), 'second replay persistence')
        # JSON expansion must survive the actual HTTP/server pipeline too.
        header = b'2026-10-25T12:00:00Z stdout F '
        payload = b'\0' * (65536-len(header)-1)
        with new.open('ab') as file:
            file.write(header+payload+b'\n')
        large = start('agent-maximum-canonical', once=True)
        require(large.wait(timeout=20) == 0 and len(calls) == 17, 'maximal native control payload admitted')
        require(calls[-1]['message'] == payload.decode(), 'canonical expansion payload preserved')
        wait(lambda: persisted(17), 'expanded payload publication')
        require(not records(spool), 'node spool empty after drain')
        empty = start('agent-final-empty', once=True)
        require(empty.wait(timeout=10) == 0 and len(calls) == 17, 'final empty restart')
        rows, findings = PIPE.snapshot(address)
        originals = {e['id']: e for e in calls}
        require(len(originals) == 15 and not findings, 'expected canonical unique records')
        require(all(e == originals[e['id']] for e in rows), 'server canonical bytes equal original pins')
        require(before == hashes(), 'source drift')
        (output / 'observations.json').write_text(json.dumps(calls, indent=2)+'\n')
        report.update(status='passed_local', original_pending_batches=[6, 6], actual_sigkill=2, withheld_successful_responses=2, profile_refusals=len(refusals), durable_malformed_oversized_skips=2, durable_gap_reasons=sorted(reasons), slot_reuse_with_unacknowledged_originals=True, canonical_replay_exact=True, persisted_event_rows=len(rows), unique_events=len(originals), wal_checkpoint=checkpoint(output / 'wal/checkpoint'), maximal_native_bytes=65536, expanded_event_bytes=len(json.dumps(calls[-1]).encode()), final_empty_restart=True, agent_sha256=digest(args.agent), server_sha256=digest(args.server))
    finally:
        release.set()
        cleanup_errors = cleanup_owned(processes, proxy, thread, server)
        report['owned_cleanup'] = not cleanup_errors
        if cleanup_errors:
            report['status'] = 'failed'
            report['cleanup_errors'] = cleanup_errors
        report['elapsed_seconds'] = round(time.monotonic()-began, 3)
        (output / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
        require(not cleanup_errors, 'owned process cleanup incomplete')
    print(json.dumps({'status': report['status'], 'report': str(output / 'report.json')}))


if __name__ == '__main__':
    main()

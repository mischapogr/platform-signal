#!/usr/bin/env python3
"""Capture audit Events in an exclusively owned kind cluster and qualify native D07.

Uses an isolated temporary kubeconfig. No AWS, caller cluster, global tool changes,
application workload execution or publication. Captures are local synthetic activity,
not proof of production audit coverage or an implemented production collector.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


LOCAL = module('audit_local_kubernetes', ROOT / 'scripts/check-kubernetes.py')
PIPELINE = module('audit_predicate_pipeline', ROOT / 'scripts/check-security-requirements.py')
require = PIPELINE.require
MAX_CAPTURE = 4 * 1024 * 1024
CASES = {'positive': ('audit', True, 1), 'negative': ('audit', False, 0),
         'metadata': ('metadata', None, 0), 'dry-run': ('audit', None, 0),
         'denied': ('restricted', None, 0)}
SOURCE_PATHS = [
    'scripts/check-kubernetes-audit.py', 'scripts/check-kubernetes.py',
    'scripts/check-security-requirements.py', 'scripts/test-kubernetes-audit.py',
    'apps/signal-server/tests/kubernetes-audit.rs',
    'crates/signal-collector-sdk/src/kubernetes_audit.rs',
    'crates/signal-collector-sdk/src/cloudtrail.rs',
    'tests/fixtures/kubernetes-audit/native.json',
    'tests/fixtures/security-requirements/catalog.json', 'Cargo.lock',
]


def hashes():
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCE_PATHS}


def checkpoint(path):
    raw = path.read_bytes()
    require(len(raw) == 28 and raw[:8] == b'SIGACK01', 'checkpoint format')
    require(zlib.crc32(raw[:24]) == int.from_bytes(raw[24:], 'little'), 'checkpoint CRC')
    require(int.from_bytes(raw[16:24], 'little') == 0, 'no WAL drop')
    return int.from_bytes(raw[8:16], 'little')


def select_records(raw):
    require(len(raw) <= MAX_CAPTURE, 'audit log byte limit')
    lines = raw.decode().splitlines()
    require(len(lines) <= 256, 'audit log record limit')
    records = [(line, json.loads(line)) for line in lines if line.strip()]
    selected = []
    positive_id = None
    for name, (namespace, privileged, findings) in CASES.items():
        matches = [(line, v) for line, v in records
                   if v.get('stage') == 'ResponseComplete'
                   and v.get('verb') == 'create'
                   and v.get('objectRef', {}).get('namespace') == namespace
                   and (v.get('objectRef', {}).get('name') == name
                        or v.get('requestObject', {}).get('metadata', {}).get('name') == name)]
        require(len(matches) == 1, 'expected one complete audit record for ' + name)
        line, v = matches[0]
        expected_code = 403 if name == 'denied' else 201
        require(v.get('responseStatus', {}).get('code') == expected_code, 'native response code for ' + name)
        if name == 'metadata':
            require(v['level'] == 'Metadata' and 'responseObject' not in v, 'native Metadata omits body')
        else:
            require(v['level'] == 'RequestResponse', 'native audit level')
        if name == 'positive':
            positive_id = v['auditID']
        selected.append({'name': name, 'raw_utf8': line,
                         'expected_privileged': privileged, 'expected_findings': findings})
    early = [(line, v) for line, v in records if v.get('auditID') == positive_id
             and v.get('stage') == 'RequestReceived']
    require(len(early) == 1, 'native request stage for positive audit ID')
    selected.append({'name': 'request-received', 'raw_utf8': early[0][0],
                     'expected_privileged': None, 'expected_findings': 0})
    return selected


class Capture:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.name = 'signal-audit-' + uuid.uuid4().hex[:12]
        self.env = os.environ.copy()
        self.env['KUBECONFIG'] = str(self.directory / 'kubeconfig')
        self.env['KIND_EXPERIMENTAL_PROVIDER'] = 'docker'
        self.attempted = False

    def run(self, args, data=None, timeout=60, expected=0):
        result = subprocess.run(args, input=data, cwd=ROOT, env=self.env,
                                capture_output=True, text=True, timeout=timeout)
        # Do not print arbitrary API bodies, credentials or command output.
        require(result.returncode == expected, 'owned audit command failed: ' + args[0])
        require(len(result.stdout.encode()) <= MAX_CAPTURE, 'command output bound')
        return result.stdout

    def kube(self, *args, data=None, expected=0):
        return self.run(['kubectl', '--context', 'kind-' + self.name,
                         '--request-timeout=15s', *args], data=data, expected=expected)

    def prepare(self):
        policy = {'apiVersion': 'audit.k8s.io/v1', 'kind': 'Policy', 'rules': [
            {'level': 'Metadata', 'namespaces': ['metadata'], 'verbs': ['create'],
             'resources': [{'group': '', 'resources': ['pods']}]},
            {'level': 'RequestResponse', 'namespaces': ['audit', 'restricted'], 'verbs': ['create'],
             'resources': [{'group': '', 'resources': ['pods']}]},
            {'level': 'None'}]}
        policy_path = self.directory / 'policy.json'
        policy_path.write_text(json.dumps(policy))
        patch = '''kind: ClusterConfiguration
apiServer:
  extraArgs:
    audit-log-path: /var/log/signal-audit/audit.log
    audit-policy-file: /etc/signal-audit/policy.json
    audit-log-mode: blocking
    audit-log-maxsize: "2"
    audit-log-maxbackup: "1"
  extraVolumes:
  - name: signal-audit-policy
    hostPath: /etc/signal-audit
    mountPath: /etc/signal-audit
    readOnly: true
    pathType: Directory
  - name: signal-audit-log
    hostPath: /var/log/signal-audit
    mountPath: /var/log/signal-audit
    pathType: DirectoryOrCreate
'''
        config = {'kind': 'Cluster', 'apiVersion': 'kind.x-k8s.io/v1alpha4',
                  'nodes': [{'role': 'control-plane', 'kubeadmConfigPatches': [patch],
                             'extraMounts': [{'hostPath': str(self.directory),
                                              'containerPath': '/etc/signal-audit', 'readOnly': True}]}]}
        config_path = self.directory / 'kind.json'
        config_path.write_text(json.dumps(config))
        self.attempted = True
        self.run(['kind', 'create', 'cluster', '--name', self.name, '--image', LOCAL.NODE_IMAGE,
                  '--config', str(config_path), '--wait', '120s'], timeout=300)
        for namespace in ['audit', 'metadata', 'restricted']:
            self.kube('create', 'namespace', namespace)
        self.kube('label', 'namespace', 'restricted', 'pod-security.kubernetes.io/enforce=restricted',
                  'pod-security.kubernetes.io/enforce-version=v1.34')
        return policy_path

    def capture(self):
        for name, (namespace, _, _) in CASES.items():
            pod = {'apiVersion': 'v1', 'kind': 'Pod',
                   'metadata': {'name': name, 'namespace': namespace},
                   'spec': {'nodeName': 'signal-audit-fixture-never-executes',
                            'containers': [{'name': 'fixture', 'image': 'example.invalid/synthetic:never',
                                            'imagePullPolicy': 'Never',
                                            'securityContext': {'privileged': name != 'negative'}}]}}
            args = ['-n', namespace, 'create', '-f', '-', '-o', 'json']
            if name == 'dry-run':
                args.append('--dry-run=server')
            self.kube(*args, data=json.dumps(pod), expected=1 if name == 'denied' else 0)
        deadline = time.monotonic() + 15
        while True:
            raw = self.run(['docker', 'exec', self.name + '-control-plane',
                            'cat', '/var/log/signal-audit/audit.log']).encode()
            try:
                return raw, select_records(raw)
            except ValueError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)

    def cleanup(self):
        if self.attempted:
            self.run(['kind', 'delete', 'cluster', '--name', self.name], timeout=120)
            names = self.run(['kind', 'get', 'clusters']).splitlines()
            require(self.name not in names, 'owned cluster cleanup')
            containers = self.run(['docker', 'ps', '-a', '--filter',
                                   'label=io.x-k8s.kind.cluster=' + self.name, '--format', '{{.ID}}'])
            require(not containers.strip(), 'owned node cleanup')


def pipeline(server, output, projection):
    output.mkdir()
    (output / 'rules').mkdir()
    catalog = json.loads((ROOT / 'tests/fixtures/security-requirements/catalog.json').read_text())
    rule = next(d['native_rule'] for d in catalog['detections'] if d['id'] == 'SIG-D07')
    (output / 'rules/D07.yaml').write_text(json.dumps(rule))
    cases = projection['cases']
    events = [case['event'] for case in cases]
    expected_events = {event['id']: event for event in events}
    expected_findings = sorted([finding for case in cases for finding in case['findings']], key=lambda f: f['id'])
    process, address = PIPELINE.start(server, output, 1)

    def settled(sequence):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(process.poll() is None, 'owned server exited')
            path = output / 'wal/checkpoint'
            if path.exists() and checkpoint(path) == sequence:
                rows, findings = PIPELINE.snapshot(address)
                require({row['id'] for row in rows} == set(expected_events), 'persisted event identities')
                require(all(row == expected_events[row['id']] for row in rows), 'persisted exact canonical events')
                require(sorted(findings, key=lambda f: f['id']) == expected_findings, 'exact deterministic D07 findings')
                return rows, findings
            time.sleep(0.03)
        raise ValueError('original WAL checkpoint did not settle')

    try:
        status, ack = PIPELINE.request(address, 'POST', '/v1/events/batch', {'events': events})
        require(status == 202 and ack['event_ids'] == [event['id'] for event in events], 'original synced admission')
        rows, findings = settled(len(events))
        process.kill()
        require(process.wait(timeout=5) == -signal.SIGKILL, 'actual owned server SIGKILL')
        process, address = PIPELINE.start(server, output, 2)
        restored, recovered = settled(len(events))
        require(sorted(restored, key=lambda e: e['id']) == sorted(rows, key=lambda e: e['id']), 'restart event bytes')
        require(recovered == findings, 'restart finding bytes')
        status, ack = PIPELINE.request(address, 'POST', '/v1/events/batch', {'events': events})
        require(status == 202 and ack['event_ids'] == [event['id'] for event in events], 'pinned redelivery admission')
        replayed, repeated = settled(len(events) * 2)
        require(repeated == findings, 'redelivery finding identity')
        process.send_signal(signal.SIGTERM)
        require(process.wait(timeout=12) == 0, 'owned server graceful stop')
        return {'unique_events': len(events), 'rows_after_redelivery': len(replayed),
                'findings': len(findings), 'wal_checkpoint': checkpoint(output / 'wal/checkpoint'),
                'actual_sigkill': True, 'exact_restart_and_redelivery': True}
    finally:
        PIPELINE.stop(process)


def execute(args):
    output = args.output.resolve()
    require(output.is_relative_to((ROOT / 'target').resolve()), 'output must be under repository target')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = hashes()
    began = time.monotonic()
    report = {'schema_version': 1, 'status': 'failed', 'source_sha256': source,
              'scope': 'local kind control-plane audit / native D07 / Small WAL restart and redelivery',
              'limits': ['test-only capture bridge; no production collector or source checkpoint',
                         'no general audit coverage, AWS/EKS, native ARM64 or remote CI qualification']}
    with tempfile.TemporaryDirectory(prefix='signal-audit-') as directory:
        capture = Capture(directory)
        try:
            policy_path = capture.prepare()
            raw, cases = capture.capture()
            (output / 'audit.log').write_bytes(raw)
            document = {'schema_version': 1, 'cluster': capture.name,
                        'policy_revision': hashlib.sha256(policy_path.read_bytes()).hexdigest(), 'cases': cases}
            input_path, projection_path = output / 'capture.json', output / 'projection.json'
            input_path.write_text(json.dumps(document, indent=2) + '\n')
            env = {k: v for k, v in os.environ.items() if not k.startswith('SIGNAL_')}
            env.update(SIGNAL_K8S_AUDIT_CAPTURE=str(input_path), SIGNAL_K8S_AUDIT_PROJECTION=str(projection_path))
            result = subprocess.run([str(args.bridge.resolve()), '--ignored', '--exact',
                                     'captured_audit_records_use_actual_normalizer_and_engine'],
                                    env=env, cwd=ROOT, capture_output=True, timeout=30)
            (output / 'bridge.log').write_bytes(result.stdout + result.stderr)
            require(result.returncode == 0 and projection_path.is_file(), 'native capture bridge failed; see bridge.log')
            projection = json.loads(projection_path.read_text())
            require(len(projection['cases']) == 6, 'six selected native audit cases')
            for case, projected in zip(cases, projection['cases'], strict=True):
                require(projected['name'] == case['name'], 'projection case order')
                require(projected['original_sha256'] == hashlib.sha256(case['raw_utf8'].encode()).hexdigest(), 'original byte hash')
            report['pipeline'] = pipeline(args.server.resolve(), output / 'pipeline', projection)
            report['capture_sha256'] = hashlib.sha256(raw).hexdigest()
            report['policy_sha256'] = document['policy_revision']
            report['native_cases'] = len(cases)
            report['cluster'] = capture.name
            report['node_image'] = LOCAL.NODE_IMAGE
            report['bridge_sha256'] = hashlib.sha256(args.bridge.read_bytes()).hexdigest()
            report['server_sha256'] = hashlib.sha256(args.server.read_bytes()).hexdigest()
            require(source == hashes(), 'source drift during capture acceptance')
            report['status'] = 'passed_local'
        finally:
            try:
                capture.cleanup()
                report['owned_cleanup'] = True
            except BaseException:
                report['status'] = 'failed'
                report['owned_cleanup'] = False
                raise
            finally:
                report['elapsed_seconds'] = round(time.monotonic() - began, 3)
                (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--bridge', required=True, type=Path, help='Compiled kubernetes-audit Rust test executable')
    parser.add_argument('--server', required=True, type=Path)
    args = parser.parse_args()
    result = execute(args)
    print(json.dumps({'status': result['status'], 'native_cases': result['native_cases'],
                      'report': str(args.output / 'report.json')}))


if __name__ == '__main__':
    main()

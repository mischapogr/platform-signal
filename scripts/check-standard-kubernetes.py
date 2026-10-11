#!/usr/bin/env python3
"""Actual Standard image in owned kind; parent owns the synthetic PostgreSQL fixture."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


KUBE = module('standard_kind', 'scripts/check-kubernetes.py')
STANDARD = module('standard_process', 'tests/integration/standard-main-process.py')


class Gate(KUBE.Gate):
    def __init__(self, args, directory, fixture):
        super().__init__(args, directory)
        self.fixture = fixture
        self.attached = False

    def request(self, path, method='GET', payload=None, authorized=True, metrics=False):
        if metrics:
            return super().request(path, method, payload, authorized, metrics)
        return STANDARD.TRANSPORT.absolute_request(
            self.fixture.context, self.port, path, 'global' if authorized else None,
            timeout=3, method=method, body=json.dumps(payload).encode() if payload is not None else None)

    def secret(self, name, contents):
        self.kube('apply', '-f', '-', data=json.dumps({
            'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name},
            'data': {key: base64.b64encode(value).decode() for key, value in contents.items()}}))

    def wal_witness(self):
        script = ('import hashlib,json,pathlib,struct,zlib;'
                  'root=pathlib.Path("/var/lib/signal/wal");data=(root/"checkpoint").read_bytes();'
                  'assert len(data)==28 and data[:8]==b"SIGACK01";'
                  'assert zlib.crc32(data[:24])==struct.unpack("<I",data[24:])[0];'
                  'print(json.dumps({"identity":hashlib.sha256((root/"identity").read_bytes()).hexdigest(),'
                  '"checkpoint":struct.unpack("<Q",data[8:16])[0]}))')
        return json.loads(self.kube('exec', self.pod()['metadata']['name'], '-c', 'synthetic-dependencies', '--', 'python3', '-c', script))

    def execute(self):
        image = json.loads(self.run(['docker', 'image', 'inspect', self.args.image]))[0]
        python = json.loads(self.run(['docker', 'image', 'inspect', self.args.fixture_image]))[0]
        KUBE.require(image['Os'] == python['Os'] == 'linux' and image['Architecture'] == python['Architecture'], 'matching Linux images')
        pg = json.loads(self.run(['docker', 'inspect', self.args.postgres]))[0]
        KUBE.require(pg['Config']['Labels'].get('signal.shared.runtime') == self.args.postgres,
                     'parent-owned PostgreSQL label')
        self.cluster_attempted = True
        self.run([self.args.kind, 'create', 'cluster', '--name', self.name,
                  '--image', KUBE.NODE_IMAGE, '--wait', '120s'], timeout=240)
        self.run(['docker', 'network', 'connect', 'kind', self.args.postgres])
        self.attached = True
        pg = json.loads(self.run(['docker', 'inspect', self.args.postgres]))[0]
        address = pg['NetworkSettings']['Networks']['kind']['IPAddress']
        for selected in (self.args.image, self.args.fixture_image):
            self.run([self.args.kind, 'load', 'docker-image', '--name', self.name, selected], timeout=180)
        self.kube('create', 'namespace', 'gate')
        f = self.fixture
        shared = json.loads((f.out / 'shared.json').read_text())
        original_stream = shared['scope']['stream']
        shared['database'].update(address=address, port=5432,
                                  producer_password_env='DB_PRODUCER_PASSWORD', reader_password_env='DB_READER_PASSWORD')
        access = json.loads(f.access.read_text())
        access['endpoint'] = 'https://127.0.0.1:18082/token'
        coverage = json.loads(f.coverage.read_text())
        coverage['directory'] = '/var/lib/signal/coverage-root'
        self.secret('runtime-config', {name: json.dumps(doc).encode() for name, doc in
                                      [('shared.json', shared), ('access.json', access), ('coverage.json', coverage)]})
        env = {'DB_PRODUCER_PASSWORD': f.password, 'DB_READER_PASSWORD': f.password,
               'SIGNAL_IDENTITY_CLIENT_SECRET': 'synthetic-standard-idp-secret',
               'SIGNAL_S3_ENDPOINT': 'http://127.0.0.1:18081', 'SIGNAL_S3_REGION': 'eu-central-1',
               'SIGNAL_S3_BUCKET': 'signal-fixture', 'SIGNAL_S3_BACKEND_ID': f.fixture_id,
               'SIGNAL_S3_ACCESS_KEY': 'synthetic-query-access', 'SIGNAL_S3_SECRET_KEY': 'synthetic-query-secret',
               'SIGNAL_S3_SESSION_TOKEN': 'synthetic-query-session', 'SIGNAL_S3_ALLOW_LOOPBACK_HTTP': 'true'}
        self.secret('runtime-credentials', {key: value.encode() for key, value in env.items()})
        ca = f.pki.private / 'standard'
        probe = f.pki.material('probe', ca / 'client', [ca], [ca / 'current.crl-der'])
        self.secret('tls-config', {'server.json': f.tls.read_bytes(), 'probe.json': probe.read_bytes()})
        certs = Path(STANDARD.BASE.read_json(f.control)['root_der']).parent
        self.secret('fixture-config', {'config.json': json.dumps({'backend_id': f.fixture_id}).encode(),
                                       'leaf.pem': (certs / 'leaf.pem').read_bytes(), 'leaf.key': (certs / 'leaf.key').read_bytes()})
        files = {}
        for source, prefix in ((f.server_root / 'wal', 'wal'), (f.out / 'coverage-root', 'coverage-root')):
            for path in sorted(source.rglob('*')):
                if path.is_dir():
                    continue
                KUBE.require(path.is_file() and not path.is_symlink(), 'regular bootstrap state')
                files[str(Path(prefix) / path.relative_to(source))] = base64.b64encode(path.read_bytes()).decode()
        bootstrap = json.dumps({'identity': {'backend': f.fixture_id, 'stream': original_stream}, 'files': files}).encode()
        KUBE.require(len(files) <= 64 and len(bootstrap) <= 512 * 1024, 'bootstrap Secret capacity')
        self.secret('bootstrap', {'files.json': bootstrap})
        self.kube('create', 'configmap', 'gate-scripts',
                  '--from-file=' + str(ROOT / 'scripts/fixtures/standard-kubernetes.py'),
                  '--from-file=' + str(ROOT / 'scripts/fixtures/s3-query-server.py'))
        self.kube('create', 'configmap', 'gate-rules', '--from-file=' + str(f.server_root / 'rules/generic.yml'))
        repository, tag = self.args.image.rsplit(':', 1)
        values = {'image': {'repository': repository, 'tag': tag, 'digest': '', 'pullPolicy': 'Never'},
                  'auth': {'existingSecret': ''}, 'tls': {'existingSecret': 'tls-config'},
                  'runtime': {'existingSecret': 'runtime-config', 'files': {'SIGNAL_SHARED_CONFIG': 'shared.json',
                    'SIGNAL_ACCESS_CONFIG': 'access.json', 'SIGNAL_COVERAGE_CONFIG': 'coverage.json'},
                    'secretEnv': [{'name': key, 'secret': 'runtime-credentials', 'key': key} for key in env]},
                  'rules': {'existingConfigMap': 'gate-rules', 'keys': ['generic.yml']},
                  'nodeSelector': {'signal-qualification-hold': self.name}}
        path = self.directory / 'values.json'
        path.write_text(json.dumps(values))
        self.run([self.args.helm, 'install', 'proof', str(ROOT / 'deploy/helm/signal'), '--values', str(path),
                  '--kube-context', 'kind-' + self.name, '--namespace', 'gate'], timeout=60)
        deployment = json.loads(self.kube('get', 'deployment', 'proof-signal', '-o', 'json'))
        podspec = deployment['spec']['template']['spec']
        security = {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                    'capabilities': {'drop': ['ALL']}}
        mounts = [{'name': 'data', 'mountPath': '/var/lib/signal'},
                  {'name': 'scripts', 'mountPath': '/scripts', 'readOnly': True}]
        podspec['initContainers'] = [{'name': 'fixture-initialize', 'image': self.args.fixture_image,
            'imagePullPolicy': 'Never', 'command': ['python3', '/scripts/standard-kubernetes.py', 'initialize'],
            'securityContext': security, 'resources': {'limits': {'memory': '64Mi', 'cpu': '250m'}},
            'volumeMounts': mounts + [{'name': 'bootstrap', 'mountPath': '/bootstrap', 'readOnly': True}]}]
        podspec['containers'].append({'name': 'synthetic-dependencies', 'image': self.args.fixture_image,
            'imagePullPolicy': 'Never', 'command': ['python3', '/scripts/standard-kubernetes.py'],
            'env': [{'name': 'PYTHONDONTWRITEBYTECODE', 'value': '1'}],
            'securityContext': security, 'resources': {'limits': {'memory': '128Mi', 'cpu': '500m'}},
            'volumeMounts': mounts + [{'name': 'fixture', 'mountPath': '/fixture', 'readOnly': True}]})
        podspec['volumes'].extend([{'name': 'scripts', 'configMap': {'name': 'gate-scripts'}},
                                  {'name': 'fixture', 'secret': {'secretName': 'fixture-config', 'defaultMode': 0o440}},
                                  {'name': 'bootstrap', 'secret': {'secretName': 'bootstrap', 'defaultMode': 0o440}}])
        del podspec['nodeSelector']
        self.kube('patch', 'deployment', 'proof-signal', '--type=json', '-p', json.dumps([
            {'op': 'replace', 'path': '/spec/template/spec', 'value': podspec}]))
        self.kube('rollout', 'status', 'deployment/proof-signal', '--timeout=110s')
        self.start_forward()
        pod = self.pod()
        claim = json.loads(self.kube('get', 'pvc', 'proof-signal', '-o', 'json'))
        volume = claim['spec']['volumeName']
        statuses = {item['name']: item for item in pod['status']['containerStatuses']}
        for name, expected in [('signal', image['Id']), ('synthetic-dependencies', python['Id'])]:
            reference = statuses[name]['imageID'].split('://')[-1]
            inspected = json.loads(self.run(['docker', 'exec', self.name + '-control-plane', 'crictl', 'inspecti', reference]))
            KUBE.require(inspected['status']['id'] == expected, 'actual runtime image identity')
        server_mounts = pod['spec']['containers'][0]['volumeMounts']
        for selector in ('SIGNAL_SHARED_CONFIG', 'SIGNAL_ACCESS_CONFIG', 'SIGNAL_COVERAGE_CONFIG'):
            KUBE.require(any(m.get('subPath') == selector + '.json' and m.get('readOnly') for m in server_mounts), 'regular runtime mount')
        for name in ('server', 'probe'):
            KUBE.require(any(m.get('subPath') == name + '.json' and m.get('mountPath') == '/etc/signal/tls/' + name + '.json'
                             and m.get('readOnly') for m in server_mounts), 'regular TLS mount')
        KUBE.require(pod['spec']['securityContext']['runAsUser'] == 65532
                     and pod['spec']['containers'][0]['securityContext']['readOnlyRootFilesystem'], 'non-root/read-only Standard server')
        KUBE.require(self.request('/v1/events', authorized=False)[0] == 401, 'unauthenticated query rejected')
        ids = []
        for account in ('a', 'b'):
            event = {'id': str(uuid.uuid4()), 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                     'source': {'type': 'query-simulation'}, 'severity': 'error', 'message': 'Standard Kubernetes ' + account,
                     'resource': {'kind': 'host', 'id': 'host-' + account, 'account_id': account},
                     'attributes': {'nested': {'preserve': [1, True, 'value']}}}
            status, body = self.request('/v1/events', 'POST', event)
            KUBE.require(status == 202 and json.loads(body)['event_ids'] == [event['id']], 'durable Standard admission')
            ids.append(event['id'])
        self.poll(lambda: {row['id'] for row in self.rows('events')} == set(ids) and len(self.rows('findings')) == 2,
                  'Standard object query and findings')
        events, findings = self.rows('events'), self.rows('findings')
        self.poll(lambda: self.wal_witness()['checkpoint'] == 2, 'synced original WAL checkpoint')
        original = self.wal_witness()
        status = statuses['signal']
        container = status['containerID'].split('://')[1]
        details = json.loads(self.run(['docker', 'exec', self.name + '-control-plane', 'crictl', 'inspect', '--output', 'json', container]))
        pid = details['info']['pid']
        KUBE.require(type(pid) is int and pid > 1, 'owned server PID')
        self.run(['docker', 'exec', self.name + '-control-plane', 'kill', '-9', str(pid)])
        self.poll(lambda: any(s['name'] == 'signal' and s['restartCount'] > status['restartCount'] and s['ready']
                             for s in self.pod()['status']['containerStatuses']), 'Standard SIGKILL restart')
        self.start_forward()
        self.poll(lambda: self.rows('events') == events and self.rows('findings') == findings, 'original Standard rows after SIGKILL')
        KUBE.require(self.wal_witness() == original, 'original WAL checkpoint after SIGKILL')
        self.kube('scale', 'deployment/proof-signal', '--replicas=0')
        self.kube('wait', '--for=delete', 'pod/' + pod['metadata']['name'], '--timeout=60s')
        self.kube('scale', 'deployment/proof-signal', '--replicas=1')
        self.kube('rollout', 'status', 'deployment/proof-signal', '--timeout=110s')
        self.start_forward()
        self.poll(lambda: self.rows('events') == events and self.rows('findings') == findings, 'original Standard rows after pod replacement')
        replacement = self.pod()
        current = self.wal_witness()
        KUBE.require(current == original and replacement['metadata']['uid'] != pod['metadata']['uid'], 'original WAL identity and replacement pod')
        KUBE.require(json.loads(self.kube('get', 'pvc', 'proof-signal', '-o', 'json'))['spec']['volumeName'] == volume, 'original PVC')
        database = self.run(['docker', 'exec', self.args.postgres, 'psql', '-X', '-U', 'postgres', '-d', 'signal_standard_main',
            '-At', '-v', 'ON_ERROR_STOP=1', '-c', 'SELECT (SELECT checkpoint FROM signal_control.partitions WHERE kind=\'pipeline\'),'
            '(SELECT wal_floor FROM signal_finding_scope.producers),(SELECT count(*) FROM signal_finding_scope.facts)']).strip()
        KUBE.require(database == '2|0|2', 'original database checkpoint/floor/scoped facts')
        return {'status': 'passed_simulated', 'scope': 'Actual local Standard Kubernetes image with synthetic identity/S3 and PostgreSQL TLS; no EKS/AWS/release proof',
                'image_id': image['Id'], 'fixture_image_id': python['Id'], 'architecture': image['Architecture'],
                'original_wal_identity_sha256': original['identity'], 'wal_checkpoint': original['checkpoint'],
                'database_witness': database, 'event_ids': ids, 'regular_config_mounts': True,
                'sigkill_recovery': True, 'replacement_pod_pvc_recovery': True}

    def cleanup(self):
        try:
            super().cleanup()
        finally:
            if self.attached:
                self.run(['docker', 'network', 'disconnect', 'kind', self.args.postgres])
                self.attached = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--fixture-image', default='python:3.13.5-alpine')
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--postgres', required=True)
    for tool in ('kind', 'helm', 'kubectl'):
        parser.add_argument('--' + tool, default=str(ROOT / 'target/kubernetes-tools' / tool))
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    fixture = STANDARD.Run(args.output.resolve(), args.server.resolve(), Path(os.environ['SIGNAL_CONTROL_FIXTURE']))
    report = {'status': 'failed', 'scope': 'Owned Standard Kubernetes gate'}
    with tempfile.TemporaryDirectory(prefix='signal-standard-kind-') as directory:
        gate = Gate(args, directory, fixture)
        try:
            fixture.start_provider()
            fixture.offline('prepare')
            fixture.endpoint = 'http://127.0.0.1:18081'
            fixture.bootstrap_coverage()
            report = gate.execute()
        except Exception:
            if gate.cluster_attempted:
                report['diagnostics'] = gate.failure_diagnostics()
            raise
        finally:
            try:
                gate.cleanup()
                report['owned_cluster_cleanup'] = True
            finally:
                fixture.cleanup_all()
                (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Standard Kubernetes process gate passed')


if __name__ == '__main__':
    main()

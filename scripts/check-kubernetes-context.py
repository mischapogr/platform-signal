#!/usr/bin/env python3
"""Actual scoped SDK API qualification in an exclusively owned disposable kind cluster."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
NODE_IMAGE = 'kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a'
SOURCE_PATHS = ['scripts/check-kubernetes-context.py', 'scripts/test-kubernetes-context.py',
                'crates/signal-collector-sdk/tests/kubernetes-context-live.rs',
                'crates/signal-collector-sdk/src/kubernetes_context/client.rs',
                'crates/signal-collector-sdk/src/kubernetes_context/mod.rs',
                'crates/signal-collector-sdk/src/kubernetes_context/projection.rs', 'Cargo.lock']


def require(value, message):
    if not value:
        raise ValueError(message)


def pod(namespace, name, node):
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'namespace': namespace, 'name': name, 'labels': {'revision': 'original'}},
            'spec': {'nodeName': node, 'automountServiceAccountToken': False,
                     'containers': [{'name': 'fixture', 'image': 'registry.k8s.io/pause:3.10'}]}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Capture:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.name = 'signal-context-' + uuid.uuid4().hex[:12]
        self.env = os.environ.copy()
        self.env['KUBECONFIG'] = str(self.directory / 'kubeconfig')
        self.env['KIND_EXPERIMENTAL_PROVIDER'] = 'docker'
        self.attempted = False
        self.process = None
        self.created = {}

    def run(self, args, data=None, timeout=45):
        result = subprocess.run(args, input=data, cwd=ROOT, env=self.env,
                                capture_output=True, text=True, timeout=timeout)
        require(result.returncode == 0, 'owned context command failed: ' + args[0])
        require(len(result.stdout.encode()) <= 4*1024*1024, 'command output bound')
        return result.stdout

    def kube(self, *args, data=None):
        return self.run(['kubectl', '--context', 'kind-' + self.name, '--request-timeout=15s', *args], data=data)

    def create(self, value):
        result = json.loads(self.kube('create', '-f', '-', '-o', 'json', data=json.dumps(value)))
        metadata = result['metadata']
        key = result['kind'] + ':' + metadata.get('namespace', '') + '/' + metadata['name']
        self.created[key] = metadata['uid']
        return result

    def prepare(self):
        self.attempted = True
        self.run(['kind', 'create', 'cluster', '--name', self.name, '--image', NODE_IMAGE, '--wait', '120s'], timeout=240)
        for ns in ['context-fixture', 'context-denied']:
            self.create({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': ns}})
        ns = 'context-fixture'
        for sa in ['context-reader', 'cluster-reader']:
            self.create({'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'namespace': ns, 'name': sa}})
        role = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': {'namespace': ns, 'name': 'context-reader'},
                'rules': [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'list', 'watch']},
                          {'apiGroups': ['rbac.authorization.k8s.io'], 'resources': ['roles', 'rolebindings'], 'verbs': ['get', 'list', 'watch']}]}
        self.create(role)
        binding = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': {'namespace': ns, 'name': 'context-reader'},
                   'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'context-reader'},
                   'subjects': [{'kind': 'ServiceAccount', 'name': 'context-reader', 'namespace': ns}]}
        self.create(binding)
        self.create({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole', 'metadata': {'name': 'context-cluster-reader'},
                     'rules': [{'apiGroups': [''], 'resources': ['nodes', 'namespaces'], 'verbs': ['get', 'list', 'watch']},
                               {'apiGroups': ['rbac.authorization.k8s.io'], 'resources': ['clusterroles', 'clusterrolebindings'], 'verbs': ['get', 'list', 'watch']}]})
        self.create({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding', 'metadata': {'name': 'context-cluster-reader'},
                     'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'context-cluster-reader'},
                     'subjects': [{'kind': 'ServiceAccount', 'name': 'cluster-reader', 'namespace': ns}]})
        self.create({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': {'namespace': ns, 'name': 'workload-role'},
                     'rules': [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get']}]})
        self.create({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': {'namespace': ns, 'name': 'workload-binding'},
                     'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'workload-role'},
                     'subjects': [{'kind': 'ServiceAccount', 'name': 'workload', 'namespace': ns}]})
        a = self.create(pod(ns, 'sample-a', 'context-fixture-node'))
        self.create(pod(ns, 'sample-b', 'context-other-node'))
        kubeconfig = json.loads(self.kube('config', 'view', '--raw', '--minify', '-o', 'json'))
        cluster = kubeconfig['clusters'][0]['cluster']
        self.origin = cluster['server']
        ca = self.directory / 'ca.pem'
        ca.write_bytes(base64.b64decode(cluster['certificate-authority-data'], validate=True))
        os.chmod(ca, 0o600)
        for sa, filename in [('context-reader', 'token'), ('cluster-reader', 'cluster-token')]:
            path = self.directory / filename
            path.write_text(self.kube('-n', ns, 'create', 'token', sa, '--duration=10m').strip())
            os.chmod(path, 0o600)
        self.ssl = ssl.create_default_context(cafile=str(ca))
        return {'initial_pod_uid': a['metadata']['uid'], 'node_filter': 'context-fixture-node', 'created_uids': dict(self.created)}

    def denied(self, method, path, body=None):
        raw = None if body is None else json.dumps(body).encode()
        token = (self.directory / 'token').read_text()
        request = urllib.request.Request(self.origin + path, data=raw, method=method,
                                        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        # No ambient proxy; credentials are confined to the explicitly owned origin.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=self.ssl))
        try:
            with opener.open(request, timeout=5) as response:
                response.read(1024)
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            require(code == 403, 'expected actual scoped permission refusal')
            return code
        raise ValueError('forbidden route unexpectedly authorized')

    def wait(self, output, marker):
        deadline = time.monotonic() + 35
        while not (output / marker).exists():
            require(self.process.poll() is None, 'native bridge exited before marker: ' + marker)
            require(time.monotonic() < deadline, 'native marker deadline: ' + marker)
            time.sleep(0.05)
        require((output / marker).stat().st_size <= 4*1024*1024, 'marker output bound')
        return json.loads((output / marker).read_text())

    def exercise(self, bridge, output):
        expected = self.prepare()
        for resource, route in [('pods', '/api/v1/namespaces/context-fixture/pods'), ('roles', '/apis/rbac.authorization.k8s.io/v1/namespaces/context-fixture/roles'), ('bindings', '/apis/rbac.authorization.k8s.io/v1/namespaces/context-fixture/rolebindings'), ('nodes', '/api/v1/nodes'), ('namespaces', '/api/v1/namespaces'), ('clusterroles', '/apis/rbac.authorization.k8s.io/v1/clusterroles'), ('clusterbindings', '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings')]:
            raw = self.kube('get', '--raw', route)
            require(len(raw.encode()) <= 1024*1024, 'native list capture limit')
            (output / ('native-' + resource + '.json')).write_text(raw)
        ns = 'context-fixture'
        denies = {}
        for method, path, body in [
            ('GET', '/api/v1/namespaces/context-denied/pods', None),
            ('GET', '/api/v1/namespaces/context-fixture/secrets', None),
            ('POST', '/api/v1/namespaces/context-fixture/pods', pod(ns, 'denied', 'context-fixture-node')),
            ('PATCH', '/api/v1/namespaces/context-fixture/pods/sample-a', {}),
            ('GET', '/api/v1/namespaces/context-fixture/pods/sample-a/log', None),
            ('POST', '/api/v1/namespaces/context-fixture/pods/sample-a/exec?command=true&container=fixture&stdout=true', None)]:
            denies[method + ' ' + path] = self.denied(method, path, body)
        config = {'origin': self.origin, 'cluster': self.name, 'namespace': ns, 'node': 'context-fixture-node',
                  'token_file': str(self.directory / 'token'), 'cluster_token_file': str(self.directory / 'cluster-token'),
                  'ca_file': str(self.directory / 'ca.pem'), 'output': str(output)}
        config_path = self.directory / 'config.json'
        config_path.write_text(json.dumps(config))
        os.chmod(config_path, 0o600)
        env = self.env.copy()
        env['SIGNAL_K8S_CONTEXT_CONFIG'] = str(config_path)
        with (output / 'bridge.log').open('xb') as log:
            self.process = subprocess.Popen([str(bridge), '--ignored', '--exact', 'owned_kind_scoped_api_and_metadata_churn', '--nocapture'], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            self.wait(output, 'pod-ready.json')
            self.kube('-n', ns, 'patch', 'pod', 'sample-a', '--type=merge', '-p', '{"metadata":{"labels":{"revision":"changed"}}}')
            self.wait(output, 'pod-modified.json')
            self.kube('-n', ns, 'delete', 'pod', 'sample-a', '--grace-period=0', '--force', '--wait=true')
            self.wait(output, 'pod-deleted.json')
            replacement = self.create(pod(ns, 'sample-a', 'context-fixture-node'))
            changed = self.wait(output, 'pod-recreated.json')
            require(replacement['metadata']['uid'] != expected['initial_pod_uid'], 'actual replacement UID differs')
            selected = [v for v in changed['collection']['objects'] if v['name'] == 'sample-a']
            require(len(selected) == 1 and selected[0]['uid'] == replacement['metadata']['uid'], 'SDK observed exact replacement UID')
            self.wait(output, 'role-ready.json')
            self.kube('-n', ns, 'patch', 'role', 'workload-role', '--type=merge', '-p', '{"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]}')
            role = self.wait(output, 'role-modified.json')
            require(any(v['name'] == 'workload-role' and v['properties']['rules'][0]['verbs'] == ['get', 'list'] for v in role['collection']['objects']), 'SDK actual changed Role rules')
            self.wait(output, 'binding-ready.json')
            self.kube('-n', ns, 'patch', 'rolebinding', 'workload-binding', '--type=merge', '-p', '{"subjects":[{"kind":"ServiceAccount","name":"workload-two","namespace":"context-fixture"}]}')
            binding = self.wait(output, 'binding-modified.json')
            require(any(v['name'] == 'workload-binding' and v['properties']['subjects'][0]['name'] == 'workload-two' for v in binding['collection']['objects']), 'SDK actual changed binding subjects')
            self.wait(output, 'revoke-ready.json')
            self.kube('-n', ns, 'delete', 'rolebinding', 'context-reader')
            # API authorization caches may take a short time to settle; only a
            # verified 403 allows the native collector revocation probe to start.
            deadline = time.monotonic() + 10
            while True:
                try:
                    self.denied('GET', '/api/v1/namespaces/context-fixture/pods')
                    break
                except ValueError:
                    require(time.monotonic() < deadline, 'revoked permission did not settle')
                    time.sleep(0.1)
            (output / 'revoked.json').write_text('{"revoked":true}')
            code = self.process.wait(timeout=35)
            require(code == 0, 'native SDK bridge failed')
        report = json.loads((output / 'report.json').read_text())
        require(report['status'] == 'passed' and all(report['checks'].values()), 'native SDK assertions passed')
        observed = {}
        for inventory in report['inventories']:
            collection = inventory['collection']
            for item in collection['objects']:
                key = collection['kind'] + ':' + (item.get('namespace') or '') + '/' + item['name']
                observed[key] = item['uid']
        for key, uid in expected['created_uids'].items():
            kind = key.split(':')[0]
            if kind in ['Pod', 'Role', 'RoleBinding', 'ClusterRole', 'ClusterRoleBinding', 'Namespace'] and 'context-denied' not in key:
                require(observed.get(key) == uid, 'SDK inventory exact owned fixture UID: ' + key)
        return {'expected': expected, 'replacement_pod_uid': replacement['metadata']['uid'], 'actual_permission_denials': denies, 'native_report': 'report.json'}

    def cleanup(self):
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            if self.attempted:
                self.run(['kind', 'delete', 'cluster', '--name', self.name], timeout=120)
                require(self.name not in self.run(['kind', 'get', 'clusters']).splitlines(), 'owned cluster cleanup')
                remaining = self.run(['docker', 'ps', '-a', '--filter', 'label=io.x-k8s.kind.cluster=' + self.name, '--format', '{{.ID}}'])
                require(not remaining.strip(), 'owned node cleanup')



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bridge', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise InterruptedError("owned campaign interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    bridge = args.bridge.resolve()
    require(bridge.is_file(), 'compiled native bridge required')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCE_PATHS}
    report = {'schema_version': 1, 'status': 'failed', 'scope': 'actual owned local kind API/RBAC/churn; no node CRI or AWS',
              'source_sha256': before, 'bridge_sha256': hashlib.sha256(bridge.read_bytes()).hexdigest(), 'node_image': NODE_IMAGE, 'cleanup': False}
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='signal-context-') as directory:
            capture = Capture(directory)
            try:
                report.update(capture.exercise(bridge, output))
                report['status'] = 'passed'
            finally:
                capture.cleanup()
                report['cleanup'] = True
        report['private_credentials_removed'] = True
        require(before == {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCE_PATHS}, 'source drift')
    except Exception as error:
        report['status'] = 'failed'
        # Exception bodies from external commands or HTTP must not leak credentials.
        report['error_type'] = type(error).__name__
        raise
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'campaign.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()

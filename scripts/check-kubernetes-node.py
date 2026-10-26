#!/usr/bin/env python3
"""Actual owned kind CRI/read-only hostPath, nonroot permissions, rotation and replay gate."""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('node_native_process', ROOT / 'scripts/check-kubernetes-node-agent.py')
LOCAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOCAL)
PIPE = LOCAL.PIPE
require = LOCAL.require
NODE_IMAGE = 'kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a'
BASE_IMAGE = 'gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2'
WORKLOAD_IMAGE = 'alpine:3.22.1'
WORKLOAD_ID = 'sha256:9234e8fb04c47cfe0f49931e4ac7eb76fa904e33b7f8576aec0501c085f02516'
AGENT_NS = 'node-agent-gate'
WORKLOAD_NS = 'node-workload-gate'
MAX_CAPTURE = 4*1024*1024
SOURCE_PATHS = [*LOCAL.SOURCE_PATHS, 'scripts/check-kubernetes-node.py', 'scripts/test-kubernetes-node.py', 'deploy/docker/Dockerfile']


def hashes():
    return {p: LOCAL.digest(ROOT / p) for p in SOURCE_PATHS}


def decode_frame(raw):
    require(12 <= len(raw) <= 1024*1024, 'native spool frame bound')
    require(len(raw) == 12+int.from_bytes(raw[:4], 'little'), 'native spool frame length')
    require(zlib.crc32(raw[:8]) == int.from_bytes(raw[8:12], 'little'), 'native spool header CRC')
    require(zlib.crc32(raw[12:]) == int.from_bytes(raw[4:8], 'little'), 'native spool CRC')
    return json.loads(raw[12:])


def parse_native(raw):
    require(0 < len(raw) <= MAX_CAPTURE and raw.endswith(b'\n'), 'complete bounded native log')
    result = []
    for line in raw.split(b'\n')[:-1]:
        fields = line.split(b' ', 3)
        require(len(fields) == 4 and fields[1] in [b'stdout', b'stderr'] and fields[2] in [b'P', b'F'], 'actual CRI framing')
        result.append({'sha256': hashlib.sha256(line+b'\n').hexdigest(), 'stream': fields[1].decode(), 'tag': fields[2].decode(), 'payload': fields[3]})
    require(len(result) <= 64, 'initial fixture physical record count')
    return result


def assert_native(events, raw, uid, node):
    require(len(events) == len(raw), 'one canonical event per initial physical record')
    for event, original in zip(events, raw):
        k = event['attributes']['kubernetes']
        log = event['attributes']['log']
        require(k['namespace'] == WORKLOAD_NS and k['pod']['runtime_uid'] == uid and k['node_name'] == node, 'native rooted source binding')
        require(log['original_sha256'] == original['sha256'] and log['stream'] == original['stream'] and log['tag'] == original['tag'], 'native physical bytes/stream/tag')
        payload = event['message'].encode() if log['payload_encoding'] == 'utf8' else base64.b64decode(log['payload_base64'], validate=True)
        require(payload == original['payload'], 'native payload exact including binary/CR')


def queried_complete(events, originals):
    return ({e['id'] for e in events} == set(originals)
            and all(e == originals[e['id']] for e in events))


class Capture:
    def __init__(self, directory, output, agent):
        self.directory = Path(directory)
        self.output = output
        self.agent = agent
        self.suffix = uuid.uuid4().hex[:12]
        self.name = 'signal-node-' + self.suffix
        self.node = self.name + '-control-plane'
        self.image = 'signal-node-fixture:' + self.suffix
        self.host_spool = '/var/lib/signal-node-gate/' + self.suffix
        self.probe = '/var/log/pods/signal-node-ro-probe-' + self.suffix
        self.env = os.environ.copy()
        self.env['KUBECONFIG'] = str(self.directory / 'kubeconfig')
        self.env['KIND_EXPERIMENTAL_PROVIDER'] = 'docker'
        self.attempted = False
        self.image_created = False
        self.restore_mode = None
        self.log_group = None

    def progress(self, stage):
        (self.output / "stage.json").write_text(json.dumps({"stage": stage, "owned_cluster": self.name})+"\n")

    def run(self, args, data=None, timeout=60, expected=0, binary=False):
        result = subprocess.run(args, input=data, cwd=ROOT, env=self.env, capture_output=True, text=not binary, timeout=timeout)
        require(result.returncode == expected, 'owned node command failed: ' + args[0])
        require(len(result.stdout) <= MAX_CAPTURE and len(result.stderr) <= MAX_CAPTURE, 'command output bound')
        return result.stdout

    def kube(self, *args, data=None, timeout=60):
        return self.run(['kubectl', '--context', 'kind-'+self.name, '--request-timeout=15s', *args], data=data, timeout=timeout)

    def docker(self, *args, binary=False):
        return self.run(['docker', 'exec', self.node, *args], binary=binary)

    def apply(self, value):
        self.kube('apply', '-f', '-', data=json.dumps(value))

    def pod(self, namespace, name):
        return json.loads(self.kube('-n', namespace, 'get', 'pod', name, '-o', 'json'))

    def terminated(self, namespace, name):
        statuses = self.pod(namespace, name).get('status', {}).get('containerStatuses', [])
        return statuses and statuses[0].get('state', {}).get('terminated')

    def prepare(self):
        image = json.loads(self.run(['docker', 'image', 'inspect', WORKLOAD_IMAGE]))[0]
        require(image['Id'] == WORKLOAD_ID and image['Os'] == 'linux' and image['Architecture'] == 'amd64', 'pinned existing workload image')
        context = self.directory / 'image'
        context.mkdir()
        shutil.copyfile(self.agent, context / 'signal-agent')
        require(LOCAL.digest(context / 'signal-agent') == LOCAL.digest(self.agent), 'exact copied ELF')
        (context / 'Dockerfile').write_text('FROM '+BASE_IMAGE+'\nLABEL org.platform-signal.fixture-owner="'+self.suffix+'"\nCOPY --chmod=755 signal-agent /usr/local/bin/signal-agent\nUSER 65532:65532\nWORKDIR /tmp\nENTRYPOINT ["/usr/local/bin/signal-agent"]\n')
        self.progress('build_fixture_image')
        self.run(['docker', 'build', '--tag', self.image, str(context)], timeout=240)
        self.image_created = True
        built = json.loads(self.run(['docker', 'image', 'inspect', self.image]))[0]
        require(built['Config']['Labels']['org.platform-signal.fixture-owner'] == self.suffix, 'owned fixture image')
        self.image_id = built['Id']
        patch = 'kind: KubeletConfiguration\ncontainerLogMaxSize: "256Ki"\ncontainerLogMaxFiles: 3\ncontainerLogMonitorInterval: "3s"\n'
        kind = {'kind': 'Cluster', 'apiVersion': 'kind.x-k8s.io/v1alpha4', 'nodes': [{'role': 'control-plane', 'kubeadmConfigPatches': [patch]}]}
        config = self.directory / 'kind.json'
        config.write_text(json.dumps(kind))
        self.attempted = True
        self.progress('create_owned_kind')
        self.run(['kind', 'create', 'cluster', '--name', self.name, '--image', NODE_IMAGE, '--config', str(config), '--wait', '120s'], timeout=240)
        self.progress('load_exact_images')
        self.run(['kind', 'load', 'docker-image', '--name', self.name, self.image, WORKLOAD_IMAGE], timeout=240)
        settings = json.loads(self.run(['docker', 'inspect', self.node]))[0]['NetworkSettings']['Networks']['kind']
        self.gateway = settings['Gateway']
        require(ipaddress.ip_address(self.gateway).version == 4, 'private kind gateway')
        root_stat = self.docker('stat', '-c', '%a %u %g', '/var/log/pods').split()
        require(len(root_stat) == 3 and all(x.isdecimal() for x in root_stat), 'native log root permissions')
        self.log_group = int(root_stat[2])
        require(0 <= self.log_group <= 4294967295, 'bounded native source supplemental group')
        (self.output / 'native-root-permissions.json').write_text(json.dumps({'mode': root_stat[0], 'uid': int(root_stat[1]), 'gid': self.log_group, 'fixture_supplemental_group': self.log_group})+'\n')
        for path in [self.host_spool+'/main', self.host_spool+'/negative']:
            self.docker('mkdir', '-p', path)
            self.docker('chown', '65532:65532', path)
            self.docker('chmod', '0700', path)
        self.docker('mkdir', '-p', self.probe)
        self.docker('chmod', '0777', self.probe)
        for namespace in [AGENT_NS, WORKLOAD_NS]:
            self.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace}})
        self.apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'namespace': AGENT_NS, 'name': 'fixture-auth'}, 'type': 'Opaque', 'data': {'token': base64.b64encode(PIPE.TOKEN.encode()).decode()}})
        settings = {}
        for line in self.docker('cat', '/var/lib/kubelet/config.yaml').splitlines():
            if line.startswith(('containerLogMaxSize:', 'containerLogMaxFiles:', 'containerLogMonitorInterval:')):
                key, value = line.split(':', 1)
                settings[key] = value.strip().strip('\"')
        require(settings == {'containerLogMaxSize': '256Ki', 'containerLogMaxFiles': '3', 'containerLogMonitorInterval': '3s'}, 'actual kubelet rotation configuration')
        return {'kubelet_log_settings': settings, 'fixture_image_id': self.image_id, 'base_image': BASE_IMAGE, 'workload_image_id': image['Id'], 'workload_repo_digests': image['RepoDigests'], 'node_image': NODE_IMAGE, 'node': self.node}

    def workload(self):
        command = r'''while [ ! -f /control/emit ]; do sleep 0.1; done
printf 'native-stdout\n'
printf 'native-stderr\r\n' >&2
printf '\360\237\n'
printf 'native-long-'; head -c 80000 /dev/zero | tr '\000' p; printf '\n'
printf 'native-initial-done\n'
while [ ! -f /control/rotate ]; do sleep 0.1; done
padding=$(head -c 1800 /dev/zero | tr '\000' r)
item=0
while [ "$item" -lt 300 ]; do printf 'native-rotate-%04d-%s\n' "$item" "$padding"; item=$((item+1)); done
printf 'native-rotation-burst-done\n'
while [ ! -f /control/after ]; do sleep 0.1; done
printf 'native-after-rotation\n'
sleep 900
'''
        self.apply({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'namespace': WORKLOAD_NS, 'name': 'workload'}, 'spec': {'nodeName': self.node, 'automountServiceAccountToken': False, 'restartPolicy': 'Never', 'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}}, 'containers': [{'name': 'fixture', 'image': WORKLOAD_IMAGE, 'imagePullPolicy': 'Never', 'command': ['sh', '-c', command], 'volumeMounts': [{'name': 'control', 'mountPath': '/control'}], 'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}}, 'resources': {'requests': {'cpu': '50m', 'memory': '16Mi'}, 'limits': {'cpu': '1', 'memory': '64Mi'}}}], 'volumes': [{'name': 'control', 'emptyDir': {}}]}})
        self.kube('-n', WORKLOAD_NS, 'wait', '--for=condition=Ready', 'pod/workload', '--timeout=60s')
        pod = self.pod(WORKLOAD_NS, 'workload')
        uid = pod['metadata']['uid']
        require(re.fullmatch('[0-9a-f-]{36}', uid), 'owned workload UID')
        self.uid = uid
        self.log = '/var/log/pods/'+WORKLOAD_NS+'_workload_'+uid+'/fixture/0.log'
        return pod

    def agent_pod(self, name, port, once=False, negative=False):
        args = ['--server', 'http://'+self.gateway+':'+str(port), '--format', 'kubernetes-cri', '--node-log-root', '/var/log/pods', '--node-name', self.node, '--node-namespace', WORKLOAD_NS, '--source-name', self.name, '--spool-dir', '/spool', '--batch-events', '1', '--flush-ms', '1', '--request-timeout-ms', '20000', '--shutdown-timeout-ms', '10000', '--metrics-listen', '0.0.0.0:9091', *(['--once'] if once else [])]
        pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'namespace': AGENT_NS, 'name': name}, 'spec': {'nodeName': self.node, 'restartPolicy': 'Never', 'automountServiceAccountToken': False, 'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532, 'supplementalGroups': [self.log_group], 'seccompProfile': {'type': 'RuntimeDefault'}}, 'containers': [{'name': 'agent', 'image': self.image, 'imagePullPolicy': 'Never', 'args': args, 'env': [{'name': 'SIGNAL_AGENT_API_TOKEN', 'valueFrom': {'secretKeyRef': {'name': 'fixture-auth', 'key': 'token'}}}], 'volumeMounts': [{'name': 'logs', 'mountPath': '/var/log/pods', 'readOnly': True}, {'name': 'spool', 'mountPath': '/spool'}], 'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}}, 'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'}, 'limits': {'cpu': '1', 'memory': '256Mi'}}}], 'volumes': [{'name': 'logs', 'hostPath': {'path': '/var/log/pods', 'type': 'Directory'}}, {'name': 'spool', 'hostPath': {'path': self.host_spool+('/negative' if negative else '/main'), 'type': 'Directory'}}]}}
        self.apply(pod)
        return pod

    def runtime_identity(self, name):
        pod = self.pod(AGENT_NS, name)
        status = pod['status']['containerStatuses'][0]
        identifier = status['containerID'].removeprefix('containerd://')
        require(re.fullmatch('[a-f0-9]{64}', identifier), 'owned runtime container ID')
        image = json.loads(self.docker('crictl', 'inspecti', status['imageID'].removeprefix('containerd://').removeprefix('docker://')))
        require(image['status']['id'] == self.image_id, 'actual runtime uses exact fixture image')
        return identifier

    def metrics(self, name):
        pod = self.pod(AGENT_NS, name)
        address = pod.get('status', {}).get('podIP')
        if not address:
            return ''
        return self.kube('-n', WORKLOAD_NS, 'exec', 'workload', '--', 'wget', '-q', '-T', '2', '-O', '-', 'http://'+address+':9091/metrics')

    def trigger(self, name):
        require(name in ['emit', 'rotate', 'after'], 'fixed owned trigger')
        self.kube('-n', WORKLOAD_NS, 'exec', 'workload', '--', 'touch', '/control/'+name)

    def spool_records(self):
        names = self.docker('find', self.host_spool+'/main', '-maxdepth', '1', '-type', 'f', '-name', 'record-*', '-printf', '%f\n').splitlines()
        require(len(names) <= 64, 'bounded native pending capture')
        result = []
        for name in sorted(names):
            require(re.fullmatch(r'record-[0-9]{20}', name), 'owned record basename')
            result.append(decode_frame(self.docker('cat', self.host_spool+'/main/'+name, binary=True)))
        return result

    def readonly_probe(self):
        command = 'error=$(touch /logs/'+self.probe.rsplit('/', 1)[1]+'/must-not-exist 2>&1); result=$?; printf "%s\\n" "$error"; test "$result" -ne 0 && printf "%s" "$error" | grep -qi "read-only file system"'
        self.apply({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'namespace': AGENT_NS, 'name': 'readonly-probe'}, 'spec': {'nodeName': self.node, 'restartPolicy': 'Never', 'automountServiceAccountToken': False, 'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532, 'supplementalGroups': [self.log_group]}, 'containers': [{'name': 'probe', 'image': WORKLOAD_IMAGE, 'imagePullPolicy': 'Never', 'command': ['sh', '-c', command], 'volumeMounts': [{'name': 'logs', 'mountPath': '/logs', 'readOnly': True}, {'name': 'tmp', 'mountPath': '/tmp'}], 'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}}], 'volumes': [{'name': 'logs', 'hostPath': {'path': '/var/log/pods', 'type': 'Directory'}}, {'name': 'tmp', 'emptyDir': {}}]}})
        LOCAL.wait(lambda: bool(self.terminated(AGENT_NS, 'readonly-probe')), 'read-only mount probe', 30)
        (self.output / 'readonly-probe.log').write_text(self.kube('-n', AGENT_NS, 'logs', 'readonly-probe', '--tail=20'))
        require(self.terminated(AGENT_NS, 'readonly-probe')['exitCode'] == 0, 'EROFS rather than discretionary permission proof')
        require(not self.docker('find', self.probe, '-maxdepth', '1', '-name', 'must-not-exist').strip(), 'readonly probe never wrote')

    def cleanup(self):
        try:
            if self.restore_mode is not None:
                self.docker('chmod', self.restore_mode, self.log)
                self.restore_mode = None
        finally:
            try:
                if self.attempted:
                    self.run(['kind', 'delete', 'cluster', '--name', self.name], timeout=120)
                    require(self.name not in self.run(['kind', 'get', 'clusters']).splitlines(), 'owned kind cleanup')
                    require(not self.run(['docker', 'ps', '-a', '--filter', 'label=io.x-k8s.kind.cluster='+self.name, '--format', '{{.ID}}']).strip(), 'owned node cleanup')
            finally:
                if self.image_created:
                    image = json.loads(self.run(['docker', 'image', 'inspect', self.image]))[0]
                    require(image['Config']['Labels']['org.platform-signal.fixture-owner'] == self.suffix, 'image cleanup ownership')
                    self.run(['docker', 'image', 'rm', self.image])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.is_relative_to((ROOT / 'target').resolve()), 'owned output under target')
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    before = hashes()
    report = {'schema_version': 1, 'status': 'failed', 'source_sha256': before, 'agent_sha256': LOCAL.digest(args.agent), 'server_sha256': LOCAL.digest(args.server), 'scope': 'actual owned kind/containerd CRI/read-only hostPath/nonroot/rotation/replay; debug fixture image', 'limits': ['local AMD64 only', 'no whole-source coverage or loss-free rotation claim', 'not production-image/current ARM64/CI,AWS/EKS or release qualification']}
    began = time.monotonic()
    server = proxy = thread = None
    release = threading.Event()
    forwarded = threading.Event()
    calls = []
    def interrupted(signum, frame):
        raise InterruptedError('owned node fixture interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        with tempfile.TemporaryDirectory(prefix='signal-node-kind-') as directory:
            capture = Capture(directory, output, args.agent.resolve())
            try:
                report.update(capture.prepare())
                capture.progress('start_owned_workload')
                workload = capture.workload()
                report['workload_uid'] = capture.uid
                (output / 'rules').mkdir()
                server, address = PIPE.start(args.server.resolve(), output, 1)
                class Proxy(BaseHTTPRequestHandler):
                    def setup(self):
                        super().setup()
                        self.connection.settimeout(3)
                    def log_message(self, *unused):
                        pass
                    def do_POST(self):
                        require(self.path == '/v1/events/batch' and self.headers.get('Authorization') == 'Bearer '+PIPE.TOKEN, 'native proxy route/auth')
                        length = int(self.headers.get('Content-Length', '0'))
                        require(0 < length <= 1024*1024 and len(calls) < 2048, 'bounded native proxy')
                        body = json.loads(self.rfile.read(length))
                        require(len(body['events']) == 1, 'one-event native fixture')
                        calls.append(body['events'][0])
                        status, ack = PIPE.request(address, 'POST', self.path, body)
                        require(status == 202, 'actual native WAL admission')
                        if len(calls) == 1:
                            forwarded.set()
                            require(release.wait(timeout=25), 'native lost-ACK deadline')
                            self.close_connection = True
                            return
                        raw = json.dumps(ack).encode()
                        self.send_response(status)
                        self.send_header('Content-Length', str(len(raw)))
                        self.end_headers()
                        self.wfile.write(raw)
                proxy = HTTPServer((capture.gateway, 0), Proxy)
                thread = threading.Thread(target=proxy.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
                thread.start()
                capture.progress('readonly_mount_probe')
                capture.readonly_probe()
                capture.progress('start_native_collector')
                capture.agent_pod('collector', proxy.server_port)
                LOCAL.wait(lambda: 'signal_agent_node_closed 0\n' in capture.metrics('collector'), 'native worker ready before emission', 45)
                container_id = capture.runtime_identity('collector')
                capture.trigger('emit')
                require(forwarded.wait(timeout=15), 'first native accepted response withheld')
                raw = capture.docker('cat', capture.log, binary=True)
                LOCAL.wait(lambda: b'native-initial-done\n' in capture.docker('cat', capture.log, binary=True), 'native initial records complete')
                raw = capture.docker('cat', capture.log, binary=True)
                (output / 'native-initial.log').write_bytes(raw)
                native = parse_native(raw)
                require({r['stream'] for r in native} == {'stdout', 'stderr'} and {'P', 'F'}.issubset({r['tag'] for r in native}), 'actual containerd stdout/stderr/P/F')
                LOCAL.wait(lambda: len(capture.spool_records()) == len(native), 'all native originals durably pending')
                pending = capture.spool_records()
                assert_native([r['event'] for r in pending], native, capture.uid, capture.node)
                (output / 'pending-originals.json').write_text(json.dumps(pending, indent=2)+'\n')
                capture.progress('native_sigkill_and_replay')
                capture.docker('crictl', 'stop', '--timeout', '0', container_id)
                LOCAL.wait(lambda: bool(capture.terminated(AGENT_NS, 'collector')), 'owned container killed', 30)
                termination = capture.terminated(AGENT_NS, 'collector')
                require(termination['exitCode'] == 137, 'actual SIGKILL exit137 witness')
                release.set()
                capture.kube('-n', AGENT_NS, 'delete', 'pod', 'collector', '--wait=true', timeout=60)
                capture.agent_pod('collector-replay', proxy.server_port, once=True)
                LOCAL.wait(lambda: bool(capture.terminated(AGENT_NS, 'collector-replay')), 'native replay completion', 45)
                require(capture.terminated(AGENT_NS, 'collector-replay')['exitCode'] == 0, 'native replay success')
                require(calls[1:] == [r['event'] for r in pending], 'exact native original pins replay')
                require(not capture.spool_records(), 'native spool drained')
                count = len(calls)
                capture.agent_pod('collector-empty', proxy.server_port, once=True)
                LOCAL.wait(lambda: bool(capture.terminated(AGENT_NS, 'collector-empty')), 'native empty restart', 30)
                require(capture.terminated(AGENT_NS, 'collector-empty')['exitCode'] == 0 and len(calls) == count, 'native cursor prevents reread')
                capture.agent_pod('collector-live', proxy.server_port)
                LOCAL.wait(lambda: 'signal_agent_node_sources 1\n' in capture.metrics('collector-live'), 'live collector ready', 30)
                previous_inode = int(capture.docker('stat', '-c', '%i', capture.log).strip())
                capture.progress('actual_kubelet_rotation')
                capture.trigger('rotate')
                LOCAL.wait(lambda: int(capture.docker('stat', '-c', '%i', capture.log).strip()) != previous_inode, 'actual kubelet rotation', 30)
                LOCAL.wait(lambda: any(e['source']['type'] == 'kubernetes.collector' and e['attributes']['collection']['reason'] in ['rotation_observed', 'compressed_generation'] for e in calls), 'native generation uncertainty persisted', 30)
                capture.trigger('after')
                LOCAL.wait(lambda: any(e.get('message') == 'native-after-rotation' for e in calls), 'new native generation collected', 30)
                capture.progress('actual_workload_deletion_and_recreation')
                old_uid, old_log = capture.uid, capture.log
                capture.kube('-n', WORKLOAD_NS, 'delete', 'pod', 'workload', '--grace-period=1', '--wait=true', timeout=60)
                def old_source_absent():
                    return capture.docker('sh', '-c', 'if test -e "$1"; then echo retained; else echo absent; fi', 'owned-probe', old_log).strip() == 'absent'
                LOCAL.wait(old_source_absent, 'actual kubelet old source removal', 90)
                LOCAL.wait(lambda: any(e['source']['type'] == 'kubernetes.collector' and e['attributes']['kubernetes']['pod']['runtime_uid'] == old_uid and e['attributes']['collection']['reason'] == 'missing_generation' for e in calls), 'actual deleted source durable gap', 30)
                capture.workload()
                require(capture.uid != old_uid, 'actual same-name workload replacement UID')
                capture.trigger('emit')
                LOCAL.wait(lambda: any(e.get('message') == 'native-initial-done' and e['attributes']['kubernetes']['pod']['runtime_uid'] == capture.uid for e in calls), 'replacement native source collected with new identity', 30)
                report.update(deleted_workload_uid=old_uid, replacement_workload_uid=capture.uid, old_source_absent=True, deletion_caused_by='actual Pod deletion and kubelet source cleanup', replacement_collected=True)
                live_id = capture.runtime_identity('collector-live')
                capture.docker('crictl', 'stop', '--timeout', '0', live_id)
                LOCAL.wait(lambda: bool(capture.terminated(AGENT_NS, 'collector-live')), 'rotation collector stopped', 30)
                # A fresh process must exercise discretionary denial; an old FD
                # would legitimately remain readable after chmod.
                capture.progress('fresh_nonroot_permission_refusal')
                original_mode = capture.docker('stat', '-c', '%a', capture.log).strip()
                require(re.fullmatch('[0-7]{3,4}', original_mode), 'owned source mode')
                capture.restore_mode = original_mode
                capture.docker('chmod', '000', capture.log)
                count = len(calls)
                capture.agent_pod('collector-denied', proxy.server_port, once=True, negative=True)
                LOCAL.wait(lambda: bool(capture.terminated(AGENT_NS, 'collector-denied')), 'nonroot read refusal', 30)
                require(capture.terminated(AGENT_NS, 'collector-denied')['exitCode'] != 0 and len(calls) == count, 'actual permission denial before send')
                capture.docker('chmod', original_mode, capture.log)
                capture.restore_mode = None
                capture.agent_pod('collector-final', proxy.server_port, once=True)
                LOCAL.wait(lambda: bool(capture.terminated(AGENT_NS, 'collector-final')), 'final node drain', 30)
                require(capture.terminated(AGENT_NS, 'collector-final')['exitCode'] == 0, 'final source restores after permissions')
                require(not capture.spool_records(), 'final native spool drained')
                query = '/v1/events?'+urlencode({'limit': '1000'})
                result = None
                originals = {e['id']: e for e in calls}
                require(0 < len(originals) < 1000, 'query covers bounded full accepted inventory')
                def persisted():
                    nonlocal result
                    status, result = PIPE.request(address, 'GET', query)
                    return status == 200 and queried_complete(result['events'], originals)
                LOCAL.wait(persisted, 'native Parquet query')
                require(queried_complete(result['events'], originals), 'all accepted native canonical records persisted exactly')
                require(before == hashes(), 'native source drift')
                report.update(status='passed_local', initial_native_records=len(native), native_streams=sorted({r['stream'] for r in native}), native_tags=sorted({r['tag'] for r in native}), readonly_hostpath_erofs=True, nonroot_uid=65532, supplemental_log_group=capture.log_group, actual_permission_refusal=True, actual_sigkill_exit_code=termination['exitCode'], exact_original_replay=True, empty_restart_no_reread=True, kubelet_rotation_observed=True, rotation_caused_by='kubelet configured256Ki/3s; workload emitted burst', initial_inode=previous_inode, final_inode=int(capture.docker('stat', '-c', '%i', capture.log).strip()), native_event_rows=len(result['events']), unique_event_ids=len({e['id'] for e in result['events']}), runtime_container_id=container_id, native_cleanup=False)
            except BaseException as error:
                diagnostic = {'error_type': type(error).__name__, 'error': str(error)[:4096], 'pods': {}}
                for namespace, name in [(AGENT_NS, 'readonly-probe'), (AGENT_NS, 'collector'), (AGENT_NS, 'collector-replay'), (AGENT_NS, 'collector-live')]:
                    try:
                        pod = capture.pod(namespace, name)
                        diagnostic['pods'][name] = {'status': pod.get('status'), 'logs': capture.kube('-n', namespace, 'logs', name, '--tail=20')}
                    except BaseException as failure:
                        diagnostic['pods'].setdefault(name, {})['diagnostic_error'] = type(failure).__name__
                (output / 'failure.json').write_text(json.dumps(diagnostic, indent=2)+'\n')
                raise
            finally:
                release.set()
                cleanup_errors = []
                for action in [
                    *([proxy.shutdown, proxy.server_close] if proxy is not None else []),
                    *([lambda: thread.join(timeout=2)] if thread is not None else []),
                    *([lambda: PIPE.stop(server)] if server is not None else []),
                    capture.cleanup,
                ]:
                    try:
                        action()
                    except BaseException as error:
                        cleanup_errors.append(type(error).__name__)
                if thread is not None and thread.is_alive():
                    cleanup_errors.append('ProxyThreadStillAlive')
                report['native_cleanup'] = not cleanup_errors
                if cleanup_errors:
                    report['status'] = 'failed'
                    report['cleanup_errors'] = cleanup_errors
                    raise RuntimeError('owned native cleanup incomplete')
        report['private_kubeconfig_removed'] = True
    finally:
        report['elapsed_seconds'] = round(time.monotonic()-began, 3)
        (output / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'status': report['status'], 'report': str(output / 'report.json')}))


if __name__ == '__main__':
    main()

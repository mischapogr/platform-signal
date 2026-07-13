#!/usr/bin/env python3
"""Finite, local Docker DAC diagnostic; public outputs contain only fixed results.

This diagnostic is deliberately separate from receiver protocol/composition
qualification. It never pulls images, builds Cargo, modifies owners or permissions
to work around a failed identity check, or treats mount absence as DAC proof.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import pwd
import grp
import resource
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE = 'sha256:14c56dcf65bcbb41d95a7ee1a8ced9464732ec71db80c014b3fab734b21cbf55'
BINARY = ROOT / 'target/goal-execution-20261007/SECURITY-AUDIT/receiver-host-stable-binary/signal-server'
PIN = '7233cb7a23b18f7de6b7436b44ce1f16fd839c84749c05345a6c7ce363677f96'
LABEL = 'signal.permission-fixture'
SMALL_FILE_CAP = 1048576
BINARY_FILE_CAP = 1073741824
PRIVATE_ENTRY_CAP = 128
PRIVATE_BYTE_CAP = 2097152
ACCEPTED_COMMIT = 'de8f846203988bc2761c144344db99156c22d3a3'
ACCEPTED_SOURCE = {
    'apps/signal-server/src/audit_receiver.rs': '69991dc5ac5bd64be9d00d8bac4aae697d55d771431f9350004b3493a9940cad',
    'apps/signal-server/src/audit_receiver/config.rs': 'e5b58c901b002a5fa654cb26826edf7b5f53be13936549e12770135e2363b7b6',
    'apps/signal-server/src/main.rs': '52feb1f418fb982d6f025f470b610236a164d9e678481dd57f877b346887a9c2',
    'apps/signal-server/Cargo.toml': '5879b49bdb2373da26b147973d184b03e94f85c1c7a28c3131ebff4a3ec802e6',
    'Cargo.lock': '4eb72b98d9043f1584f909b9dd6ac5cdd7742b08a8f1165200fdf38d0805854d',
    'apps/signal-server/src/audit_receiver/tests.rs': '80bf21d3f6aeb3af51c60a5f91a06b1be79e0f41df93c96e17a45c1301ff5382',
}

def consume_regular(path, cap, consume):
    """Reject special/symlink inputs before open; cap bytes even if input grows."""
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > cap:
        raise RuntimeError('regular_file_input_capacity')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    def identity(value):
        return (value.st_dev,value.st_ino,value.st_mode,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(metadata):
            raise RuntimeError('regular_file_identity_changed')
        used = 0
        while True:
            block = os.read(fd, min(65536, cap - used + 1))
            if not block: break
            used += len(block)
            if used > cap: raise RuntimeError('regular_file_read_capacity')
            consume(block)
        if used != opened.st_size or identity(os.fstat(fd)) != identity(opened):
            raise RuntimeError('regular_file_changed_during_read')
        return used
    finally: os.close(fd)

def digest(path, cap=SMALL_FILE_CAP):
    h = hashlib.sha256()
    consume_regular(path, cap, h.update)
    return h.hexdigest()

def private_snapshot(root, max_entries=PRIVATE_ENTRY_CAP, max_bytes=PRIVATE_BYTE_CAP):
    """Incrementally bounded inventory; never materialize a recursive glob."""
    result, entries, used = {}, 0, 0
    pending = [pathlib.Path(root)]
    while pending:
        directory = pending.pop()
        if not stat.S_ISDIR(os.lstat(directory).st_mode):
            raise RuntimeError('private_inventory_directory_type')
        with os.scandir(directory) as children:
            for entry in children:
                entries += 1
                if entries > max_entries: raise RuntimeError('private_inventory_entry_capacity')
                metadata = entry.stat(follow_symlinks=False)
                path = pathlib.Path(entry.path)
                if stat.S_ISDIR(metadata.st_mode): pending.append(path)
                elif stat.S_ISREG(metadata.st_mode):
                    h = hashlib.sha256()
                    used += consume_regular(path, min(SMALL_FILE_CAP, max_bytes-used), h.update)
                    result[path.relative_to(root).as_posix()] = h.hexdigest()
                else: raise RuntimeError('private_inventory_file_type')
    return result

def bounded_store_entries(root):
    result = []
    with os.scandir(root) as entries:
        for entry in entries:
            if len(result) >= 4: raise RuntimeError('initialized_store_entry_capacity')
            result.append(entry)
    return result

def read_provenance(path):
    raw = bytearray()
    consume_regular(path, 65536, raw.extend)
    value = json.loads(raw)
    if value.get('sha256') != PIN or value.get('source_sha256') != ACCEPTED_SOURCE or value.get('binary') != str(BINARY):
        raise RuntimeError('accepted_binary_provenance_mismatch')
    return value

def valid_identity(value, uid, gid):
    return (uid > 0 and gid > 0 and value.get('Uid') == [uid] * 4
            and value.get('Gid') == [gid] * 4 and value.get('NoNewPrivs') == [1]
            and int(value.get('CapEff', '1'), 16) == 0
            and set(value.get('Groups', [])) <= {gid})

def role_identities(uid, gid):
    if uid <= 0 or gid <= 0: raise RuntimeError('nonzero_host_owner_required')
    roles = [(uid, gid)]
    for candidate in range(max(uid, gid) + 1, min(max(uid, gid) + 65, 65534)):
        try: pwd.getpwuid(candidate); continue
        except KeyError: pass
        try: grp.getgrgid(candidate); continue
        except KeyError: pass
        roles.append((candidate, candidate))
        if len(roles) == 4: return roles
    raise RuntimeError('unused_nonzero_role_identity_capacity')

def valid_probe(value, uid, gid, owner, positive=False):
    expected = {'root-list'} | {name + '-' + op for name in ('control', 'journal', 'config', 'key', 'secret') for op in ('read', 'write')}
    if not positive: expected.add('root-create')
    rows = value.get('results', [])
    return (valid_identity(value.get('identity', {}), uid, gid)
            and valid_identity(value.get('pid1_identity', {}), uid, gid)
            and value.get('root_owner') == owner and value.get('root_mode') == 0o700
            and len(rows) == len(expected) and {r.get('name') for r in rows} == expected
            and all(r.get('errno') == 0 if positive else r.get('errno') in (1, 13) for r in rows))

class Bounded:
    def __init__(self):
        self.deadline = time.monotonic() + 180
        self.commands = 0
        self.owner = uuid.uuid4().hex
        self.names = []
        self.children = set()
        self.cleanup_errors = []

    def retire_child(self, child):
        # returncode means Popen already reaped this leader. Never send a signal
        # to that numeric PID/group, which could now belong to another process.
        if child.returncode is not None:
            self.children.discard(child)
            return True
        try:
            # An externally reaped/unknown child cannot pin its PID; retain the
            # uncertain registry entry rather than risking a reused process ID.
            os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            child.wait(timeout=2)
        except Exception:
            self.cleanup_errors.append('child_retirement_uncertain')
            return False
        self.children.discard(child)
        return True

    def command(self, args, cleanup=False, limit=1048576):
        if not cleanup:
            if self.commands >= 48 or time.monotonic() >= self.deadline - 30:
                raise RuntimeError('command_or_original_deadline_capacity')
        if self.commands >= 64: raise RuntimeError('cleanup_command_capacity')
        self.commands += 1
        # Disk-backed private capture bounds memory and avoids pipe deadlock.
        with tempfile.TemporaryFile() as output:
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
            try:
                def file_capacity():
                    resource.setrlimit(resource.RLIMIT_FSIZE, (limit + 1, limit + 1))
                child = subprocess.Popen(args, stdout=output, stderr=output, start_new_session=True, preexec_fn=file_capacity)
                self.children.add(child)
            finally: signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            until = min(self.deadline, time.monotonic() + 10)
            try:
                while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    if time.monotonic() >= until or output.tell() > limit:
                        raise RuntimeError('command_time_or_output_capacity')
                    time.sleep(.025)
                if output.tell() > limit: raise RuntimeError('command_output_capacity')
                # Kill the owned group while the exited leader still pins its PID,
                # then reap; descendants cannot outlive a successful command.
                if not self.retire_child(child): raise RuntimeError('owned_child_retirement_uncertain')
                output.seek(0)
                raw = output.read(limit + 1)
                return child.returncode, raw
            finally:
                # Retire owned group before reaping its leader, including interruption.
                if child in self.children: self.retire_child(child)

    def docker(self, *args, cleanup=False, limit=1048576):
        return self.command(['docker', *args], cleanup, limit)

    def create(self, role, uid, gid, private, probe, args):
        name = 'signal-perm-' + self.owner[:12] + '-' + role
        self.names.append(name)  # Reservation precedes uncertain creation.
        mounts = []
        for source, target, ro in ((probe, '/probe', True), (BINARY, '/server', True),
                                   (private / 'root', '/restricted/root', False),
                                   (private / 'config', '/restricted/config', False),
                                   (private / 'key', '/restricted/key', False),
                                   (private / 'secret', '/restricted/secret', False),
                                   (private / 'health-tls', '/restricted/health-tls', True)):
            mounts += ['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if ro else '')]
        environment = ['--env-file', str(private/'environment')] if role == 'receiver' else []
        code, _ = self.docker('create', '--pull=never', '--name', name, '--label', LABEL + '=' + self.owner,
                             '--user', f'{uid}:{gid}', '--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges',
                             '--network=none', '--no-healthcheck', '--memory=128m', '--pids-limit=32', '--cpus=1',
                             '--entrypoint', '/probe', *environment, *mounts, IMAGE, *args)
        if code: raise RuntimeError('container_create_failed')
        return name

    def cleanup(self):
        for child in list(self.children):
            self.retire_child(child)
        for name in reversed(tuple(self.names)):
            try:
                code, raw = self.docker('inspect', '--format', '{{json .Config.Labels}}', name, cleanup=True, limit=65536)
                if code:
                    # Only an exact daemon NotFound is absence proof.
                    if code == 1 and raw == b'Error: No such object: ' + name.encode() + b'\n':
                        self.names.remove(name)
                        continue
                    self.cleanup_errors.append('container_inspection_uncertain'); continue
                if json.loads(raw).get(LABEL) != self.owner:
                    self.cleanup_errors.append('container_owner_mismatch'); continue
                code, _ = self.docker('rm', '-f', name, cleanup=True)
                if code: self.cleanup_errors.append('container_removal_uncertain')
                else: self.names.remove(name)
            except BaseException: self.cleanup_errors.append('cleanup_exception')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = {'schema_version': 1, 'status': 'failed', 'scope': 'bounded LinuxAMD64 debug DAC simulation only', 'checks': [],
              'limitations': ['Protocol/TLS, native monolith/outage and independent health composition are separate and NOT run by this DAC helper.',
                              'Other UID containers run DAC probes, not actual monolith/producer/health-owner applications.',
                              'Application logs are discarded, so no full application-log privacy claim is made.',
                              'No production/separate host-user/daemon-admin/nativeARM/cloud/release-image qualification.']}
    started = time.monotonic(); runner = Bounded()
    private = pathlib.Path(tempfile.mkdtemp(prefix='signal-receiver-permissions-'))
    source = ROOT / 'tests/fixtures/audit-receiver-permissions.rs'
    inputs = [source, pathlib.Path(__file__), ROOT / 'scripts/test-audit-receiver-permissions.py',
              BINARY.with_name('binary.json'), ROOT/'tests/integration/transport-server-process.py',
              ROOT/'scripts/check-access-idp.py', ROOT/'scripts/check-native-qualification.py']
    before = {}
    def check(name, condition):
        if not condition: raise AssertionError(name)
        report['checks'].append({'name': name, 'status': 'passed'})
    def interrupted(*_): raise RuntimeError('owned_signal_interruption')
    old = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        before = {str(p.relative_to(ROOT)): digest(p) for p in inputs}
        check('immutable-native-binary-pin', digest(BINARY, BINARY_FILE_CAP) == PIN)
        report['binary_sha256'] = PIN
        report['binary_source_provenance'] = read_provenance(BINARY.with_name('binary.json'))
        report['accepted_source_commit'] = ACCEPTED_COMMIT
        check('accepted-binary-source-provenance', report['binary_source_provenance']['source_sha256'] == ACCEPTED_SOURCE)
        uid, gid = os.getuid(), os.getgid()
        identities = role_identities(uid, gid)
        check('four-distinct-unused-nonzero-role-identities', len(set(identities)) == 4)
        report['roles'] = {r: {'uid': pair[0], 'gid': pair[1]} for r, pair in zip(('receiver','monolith','producer','health'), identities)}
        code, raw = runner.docker('info', '--format', '{{json .SecurityOptions}}', limit=65536)
        check('daemon-security-inspection', code == 0)
        report['daemon_security_options'] = json.loads(raw)
        code, raw = runner.docker('image', 'inspect', IMAGE, '--format', '{{json .Id}} {{json .Os}} {{json .Architecture}}', limit=65536)
        check('cached-native-immutable-substrate', code == 0 and raw.decode().strip() == f'"{IMAGE}" "linux" "amd64"')
        report['substrate_image'] = IMAGE
        probe = args.output.resolve() / 'permission-probe'
        code, _ = runner.command(['rustc', '--edition=2021', '-O', '-C', 'strip=symbols', str(source), '-o', str(probe)])
        check('standalone-probe-compile', code == 0)
        # Public fixture code must execute under every role; private mounts stay
        # 0700/0600. The containing host evidence directory remains 0700.
        probe.chmod(0o555)
        report['probe_sha256'] = digest(probe)
        (private/'root').mkdir(mode=0o700)
        # Reuse only the finite synthetic certificate preparation contract. No
        # source mutation, ordinary host server process or socket is required.
        transport_path = ROOT/'tests/integration/transport-server-process.py'
        spec = importlib.util.spec_from_file_location('permission_transport', transport_path)
        transport = importlib.util.module_from_spec(spec); spec.loader.exec_module(transport)
        certs = object.__new__(transport.Run); certs.private = private
        def openssl(*values):
            code, _ = runner.command(['openssl', *map(str, values)], limit=65536)
            if code: raise RuntimeError('private_certificate_preparation_failed')
        certs.openssl = openssl
        append_ca, health_ca = certs.ca('append'), certs.ca('health')
        append_server = certs.leaf(append_ca, 'append-server', 'serverAuth')
        health_server = certs.leaf(health_ca, 'health-server', 'serverAuth')
        (private/'key').write_bytes(certs.material('append-tls', append_server, [append_ca]).read_bytes())
        (private/'health-tls').write_bytes(certs.material('health-material', health_server, [health_ca]).read_bytes())
        (private/'secret').write_text('synthetic-permission-health-credential\n')
        (private/'environment').write_text('PERMISSION_APPEND=synthetic-permission-append-credential\nPERMISSION_HEALTH=synthetic-permission-health-credential\n')
        configuration = {'schema_version':1, 'directory':'/restricted/root',
                         'append':{'listen':'127.0.0.1:8081','tls_config':'/restricted/key','max_connections':2},
                         'health':{'listen':'127.0.0.1:8082','tls_config':'/restricted/health-tls','max_connections':1},
                         'producers':[{'producer_id':str(uuid.uuid4()),'credential_env':'PERMISSION_APPEND'}],
                         'health_credential_env':'PERMISSION_HEALTH','max_bytes':65536,'max_records':16,
                         'request_timeout_ms':500,'header_timeout_ms':500,'connection_timeout_ms':1000,'shutdown_timeout_ms':500}
        (private/'config').write_text(json.dumps(configuration))
        report['certificate_helper_sha256'] = digest(transport_path)
        snapshot = None
        report['protected_fixture'] = 'actual pinned receiver initialized control/journal, private server profile/TLS key and health secret'
        for i, role in enumerate(('receiver','monolith','producer','health')):
            role_uid, role_gid = identities[i]
            name = runner.create(role, role_uid, role_gid, private, probe, ['hold'])
            code, _ = runner.docker('start', name); check(role+'-start', code == 0)
            code, raw = runner.docker('inspect', '--format', '{{json .Config.User}} {{json .HostConfig.ReadonlyRootfs}} {{json .HostConfig.Privileged}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}} {{json .HostConfig.NetworkMode}}', name, limit=65536)
            values = json.JSONDecoder(); rest = raw.decode().strip(); items=[]
            while rest:
                value, pos = values.raw_decode(rest); items.append(value); rest=rest[pos:].lstrip()
            check(role+'-configured-fences', code == 0 and items == [f'{role_uid}:{role_gid}',True,False,['ALL'],['no-new-privileges'],'none'])
            if i == 0:
                code, _ = runner.docker('exec', name, '/server', '--initialize-audit-receiver', '--config', '/restricted/config', limit=65536)
                entries = bounded_store_entries(private/'root')
                names = {p.name for p in entries}
                report['initialization'] = {'exit_code':code,'control_present':'control' in names,'journal_present':'journal' in names,'lock_present':'lock' in names,'file_count':len(names)}
                check('actual-pinned-receiver-initialization', code == 0 and names == {'control','journal','lock'})
                check('actual-receiver-private-store-modes', all(stat.S_ISREG(p.stat(follow_symlinks=False).st_mode) and p.stat(follow_symlinks=False).st_mode & 0o777 == 0o600 for p in entries))
                snapshot = private_snapshot(private)
            code, raw = runner.docker('exec', name, '/probe', 'owner' if i == 0 else 'deny', limit=65536)
            result = json.loads(raw)
            check(role+'-actual-identity-and-dac', code == 0 and valid_probe(result,role_uid,role_gid,uid,positive=i==0))
            report['checks'][-1]['actual'] = result
            check(role+'-protected-content-unchanged', snapshot == private_snapshot(private))
            if i == 0:
                code, raw = runner.docker('exec', name, '/server', '--help', limit=65536)
                check('actual-pinned-debug-server-load', code == 0 and b'--audit-receiver' in raw)
                code, raw = runner.docker('exec', name, '/probe', 'receiver-process', limit=65536)
                result = json.loads(raw)
                check('actual-existing-receiver-process-identity', code == 0 and valid_probe(result,uid,gid,uid,positive=True))
                report['checks'][-1]['actual'] = result
                check('existing-receiver-preserves-initialized-history', snapshot == private_snapshot(private))
        report['status'] = 'passed_dac_simulated'
    except BaseException as error:
        report['failure'] = {'kind':type(error).__name__, 'phase': str(error) if isinstance(error,(AssertionError,RuntimeError)) else 'typed_fixture_failure'}
    finally:
        # Cleanup must proceed even when another signal arrives.
        for s in old: signal.signal(s, signal.SIG_IGN)
        runner.cleanup()
        if not runner.cleanup_errors: shutil.rmtree(private)
        else: report['private_recovery_required'] = True
        for s,h in old.items(): signal.signal(s,h)
        report.update(cleanup_errors=runner.cleanup_errors, docker_and_compile_command_count=runner.commands,
                      source_sha256=before, elapsed_seconds=time.monotonic()-started,
                      passed_check_count=len(report['checks']))
        try:
            report['input_guards_match'] = bool(before) and before == {str(p.relative_to(ROOT)):digest(p) for p in inputs} and digest(BINARY,BINARY_FILE_CAP)==PIN
        except Exception: report['input_guards_match'] = False
        if runner.cleanup_errors or not report['input_guards_match']: report['status']='failed'
        (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:report[k] for k in ('status','passed_check_count','cleanup_errors','input_guards_match','elapsed_seconds')}))
    return 0 if report['status']=='passed_dac_simulated' else 1

if __name__ == '__main__': raise SystemExit(main())

#!/usr/bin/env python3
"""Finite, owned Keycloak/OIDC/browser -> actual SIGNAL qualification.

The IdP and browser are test dependencies, never production SIGNAL services.
Only synthetic credentials are created, in a private scratch root removed on exit.
"""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import shutil
import tempfile
import threading
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'quay.io/keycloak/keycloak@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc'
SPEC = importlib.util.spec_from_file_location('signal_identity_owner', ROOT / 'tests/integration/access-server-process.py')
OWN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWN)
NATIVE_SPEC = importlib.util.spec_from_file_location('signal_idp_commands', ROOT / 'scripts/check-native-qualification.py')
NATIVE = importlib.util.module_from_spec(NATIVE_SPEC)
NATIVE_SPEC.loader.exec_module(NATIVE)
SUBJECTS = {a: str(uuid.UUID(int=0x50000000000040008000000000000000 + i))
            for i, a in enumerate(('a', 'b', 'unbound', 'admin'), 1)}


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def private_json(path, value):
    with path.open('x') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream)


def discovery(opener, url, budget):
    """Main-thread Linux gate: one absolute budget includes headers and body."""
    def expired(_kind, _frame):
        raise TimeoutError('discovery request deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, budget)
    try:
        with opener.open(url, timeout=min(1, budget)) as reply:
            raw = reply.read(65537)
        if len(raw) > 65536:
            raise ValueError('discovery byte capacity')
        return json.loads(raw)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def realm(callback, secrets):
    clients = []
    for name, audience, lifetime in [('signal-fixture', 'signal', 60),
                                     ('wrong-audience', 'other', 60),
                                     ('short-lease', 'signal', 4)]:
        clients.append({'clientId': name, 'secret': secrets[name], 'enabled': True,
            'protocol': 'openid-connect', 'publicClient': False,
            'standardFlowEnabled': True, 'directAccessGrantsEnabled': False,
            'implicitFlowEnabled': False, 'serviceAccountsEnabled': False,
            'redirectUris': [callback], 'webOrigins': [],
            'attributes': {'pkce.code.challenge.method': 'S256', 'access.token.lifespan': str(lifetime)},
            # Keycloak >=26.6.2 requires the introspecting client in aud.
            # Keep the resource audience independently selected; wrong-audience
            # tokens remain introspectable but lack SIGNAL's resource audience.
            'protocolMappers': [{'name': 'synthetic-audience-' + str(index), 'protocol': 'openid-connect',
                'protocolMapper': 'oidc-audience-mapper', 'config': {
                    'included.custom.audience': value, 'access.token.claim': 'true',
                    'id.token.claim': 'false', 'introspection.token.claim': 'true'}}
                for index, value in enumerate(dict.fromkeys((audience, name, 'signal-fixture')))]})
    return {'realm': 'signal-fixture', 'enabled': True, 'sslRequired': 'all',
        'registrationAllowed': False, 'resetPasswordAllowed': False,
        'accessTokenLifespan': 60, 'clients': clients,
        'roles': {'realm': [{'name': 'forged-global'}]},
        'users': [{'id': subject, 'username': 'fixture-' + account, 'enabled': True,
            'emailVerified': True, 'firstName': 'Synthetic', 'lastName': account,
            'email': 'fixture-' + account + '@example.test', 'requiredActions': [],
            'realmRoles': ['forged-global'],
            'credentials': [{'type': 'password', 'value': secrets['password'], 'temporary': False}]}
            for account, subject in SUBJECTS.items()]}


def policy(issuer):
    roles, bindings = [], []
    for account in ('a', 'b'):
        scope = {key: {'mode': 'only', 'values': [value]} for key, value in
                 [('sources', 'synthetic-idp'), ('accounts', account), ('resources', 'resource-' + account)]}
        roles.append({'id': 'fixture-' + account, 'permissions': [
            {'operation': op, 'scope': scope} for op in ('ingest_events', 'query_events', 'read_findings')]})
        bindings.append({'issuer': issuer, 'subject': SUBJECTS[account], 'roles': ['fixture-' + account]})
    all_scope = {key: {'mode': 'all'} for key in ('sources', 'accounts', 'resources')}
    roles.append({'id': 'fixture-admin', 'permissions': [{'operation': op, 'scope': all_scope}
        for op in ('configure', 'manage_rules', 'read_audit', 'read_evidence', 'read_findings_feed')]})
    bindings.append({'issuer': issuer, 'subject': SUBJECTS['admin'], 'roles': ['fixture-admin']})
    return {'schema_version': 1, 'roles': roles, 'bindings': bindings}


class OwnedGroups:
    """At most three leaders, bounded drains, no PID reaping before group kill."""
    def __init__(self, output):
        self.output = output
        self.children, self.drains, self.logs, self.errors = {}, {}, [], []
        self.reservations = threading.Lock()

    def spawn(self, command, environment, label):
        if len(self.children) >= 3 or len(self.logs) >= 8:
            raise RuntimeError('owned process capacity')
        path = self.output / (label + '.log')
        if path.exists():
            raise RuntimeError('fresh process log required')
        with NATIVE.defer_spawn_signals():
            child = subprocess.Popen(command, cwd=ROOT, env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True)
            self.children[child.pid] = child
            self.logs.append(path)

            def drain():
                try:
                    retained = 0
                    with path.open('xb') as stream:
                        while True:
                            chunk = child.stdout.read1(8192)
                            if not chunk:
                                break
                            remaining = 1024 * 1024 - retained
                            stream.write(chunk[:remaining]); stream.flush()
                            retained += min(remaining, len(chunk))
                            if len(chunk) > remaining:
                                self.errors.append('process output capacity')
                                with self.reservations:
                                    if child.pid in self.children:
                                        os.killpg(child.pid, signal.SIGKILL)
                                break
                except Exception:
                    self.errors.append('process output drain failed')
                finally:
                    child.stdout.close()

            thread = threading.Thread(target=drain, daemon=True, name='signal-idp-' + label)
            self.drains[child.pid] = thread
            thread.start()
        return child

    def exited(self, child):
        if child.pid not in self.children or child.returncode is not None:
            raise RuntimeError('owned leader reservation lost')
        return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def stop(self, child):
        if child.pid not in self.children or child.returncode is not None:
            raise RuntimeError('owned leader reservation lost')
        # The reserved leader PID keeps its process group safe against reuse.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 2
        while self.exited(child) is None and time.monotonic() < deadline:
            time.sleep(0.02)
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        with self.reservations:
            code = child.wait(timeout=3)
            # Reaping releases the PID. Remove signalling authority immediately,
            # before any drain operation can fail; retries may only join drains.
            self.children.pop(child.pid)
        thread = self.drains.get(child.pid)
        if thread is not None and thread.ident is not None:
            thread.join(timeout=1)
            if thread.is_alive():
                raise RuntimeError('owned process drain did not finish')
        elif child.stdout is not None:
            child.stdout.close()
        self.drains.pop(child.pid, None)
        return code

    def check(self):
        if self.errors:
            raise RuntimeError('owned process output failed')

    def cleanup(self):
        errors = []
        for child in list(self.children.values()):
            try:
                self.stop(child)
            except Exception as exc:
                errors.append('owned process cleanup: ' + type(exc).__name__)
        for pid, thread in list(self.drains.items()):
            if pid not in self.children:
                try:
                    if thread.ident is not None:
                        thread.join(timeout=1)
                    if thread.is_alive():
                        errors.append('owned process drain remains')
                    else:
                        self.drains.pop(pid)
                except Exception as exc:
                    errors.append('owned drain cleanup: ' + type(exc).__name__)
        errors.extend(self.errors)
        return errors


class Run:
    def __init__(self, output):
        if output.exists():
            raise ValueError('fresh output directory required')
        output.mkdir(parents=True, mode=0o700)
        self.output = output
        self.generation = str(uuid.uuid4())
        self.name = 'signal-idp-' + self.generation
        self.owner = OwnedGroups(output)
        self.container_attempted = False
        self.image_attempted = False
        self.image_name = 'platform-signal-idp:' + self.generation
        self.cleanup_errors = []
        self.stage = 'prepare'
        self.command_failures = 0

    def command(self, args, timeout=10, absent_message=None):
        # Reuse finite output/deadline and owned process-group cleanup.
        import io
        log = io.BytesIO()
        try:
            NATIVE.run_bounded(args, log, timeout=timeout, grace=0.1)
        except (Exception, KeyboardInterrupt) as exc:
            if self.command_failures < 8:
                self.command_failures += 1
                (self.output / ('command-failure-' + str(self.command_failures) + '.log')).write_bytes(log.getvalue())
            if (absent_message is not None and type(exc) is RuntimeError
                    and str(exc) == 'command failed with exit 1'
                    and log.getvalue().decode('utf-8').strip() in absent_message):
                return None
            raise
        return log.getvalue().decode('utf-8').strip()

    def container_owned(self):
        value = self.command(['docker', 'inspect', '--format',
            '{{ index .Config.Labels "org.platform-signal.idp-owner" }}', self.name], timeout=2,
            absent_message=('Error: No such object: ' + self.name,
                            'error: no such object: ' + self.name))
        if value is None:
            return False
        if value != self.generation:
            raise RuntimeError('container ownership mismatch')
        return True

    def control(self, operation):
        if operation not in ('pause', 'unpause') or not self.container_owned():
            raise RuntimeError('provider control ownership')
        self.command(['docker', operation, self.name])

    def cleanup(self):
        # Children first, then only this exact labelled synthetic IdP.
        self.cleanup_errors.extend(self.owner.cleanup())
        if self.container_attempted:
            try:
                if self.container_owned():
                    self.command(['docker', 'rm', '-f', self.name], timeout=3)
                if self.container_owned():
                    self.cleanup_errors.append('owned container remains')
            except Exception as exc:
                self.cleanup_errors.append('container cleanup: ' + type(exc).__name__)
        if self.image_attempted:
            try:
                value = self.command(['docker', 'image', 'inspect', '--format',
                    '{{ index .Config.Labels "org.platform-signal.idp-owner" }}', self.image_name], timeout=2,
                    absent_message=('Error response from daemon: No such image: ' + self.image_name,
                                    'error: no such image: ' + self.image_name))
                if value is not None and value != self.generation:
                    raise RuntimeError('test image ownership mismatch')
                if value is not None:
                    self.command(['docker', 'image', 'rm', self.image_name], timeout=3)
            except Exception as exc:
                self.cleanup_errors.append('test image cleanup: ' + type(exc).__name__)

    def execute(self, args, scratch):
        port, callback_port = free_port(), free_port()
        origin = 'https://127.0.0.1:' + str(port)
        issuer = origin + '/realms/signal-fixture'
        callback = 'https://127.0.0.1:' + str(callback_port) + '/callback'
        secrets = {key: 'synthetic-' + uuid.uuid4().hex for key in
                   ('signal-fixture', 'wrong-audience', 'short-lease', 'password')}
        certs = scratch / 'certs'; certs.mkdir(mode=0o755)
        imports = scratch / 'imports'; imports.mkdir(mode=0o755)
        for command in [
            ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
             '-keyout', str(certs / 'root.key'), '-out', str(certs / 'root.pem'), '-days', '1',
             '-subj', '/CN=synthetic-local-idp-ca', '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,keyCertSign,cRLSign'],
            ['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
             '-keyout', str(certs / 'leaf.key'), '-out', str(certs / 'leaf.csr'), '-subj', '/CN=synthetic-local-idp'],
        ]:
            self.command(['openssl', *command])
        (certs / 'leaf.ext').write_text('subjectAltName=IP:127.0.0.1\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n')
        self.command(['openssl', 'x509', '-req', '-in', str(certs / 'leaf.csr'), '-CA', str(certs / 'root.pem'),
            '-CAkey', str(certs / 'root.key'), '-set_serial', '2', '-days', '1', '-extfile', str(certs / 'leaf.ext'),
            '-out', str(certs / 'leaf.pem')])
        # Only this synthetic leaf is readable by the unprivileged container.
        os.chmod(certs / 'leaf.key', 0o444)
        private_json(imports / 'signal-fixture-realm.json', realm(callback, secrets))
        os.chmod(imports / 'signal-fixture-realm.json', 0o444)
        image = json.loads(self.command(['docker', 'image', 'inspect', '--format',
            '{"id":{{json .Id}},"architecture":{{json .Architecture}}}', IMAGE]))
        self.stage = 'image-prepare'
        self.image_attempted = True
        self.command(['docker', 'build', '--network=none', '--label',
            'org.platform-signal.idp-owner=' + self.generation,
            '-t', self.image_name, '-f', str(ROOT / 'tools/identity/Containerfile'),
            str(ROOT / 'tools/identity')], timeout=120)
        prepared = self.command(['docker', 'image', 'inspect', '--format', '{{.Id}}', self.image_name])
        self.stage = 'provider-start'
        self.container_attempted = True  # Own the unique name before daemon mutation.
        self.command(['docker', 'run', '-d', '--pull=never', '--name', self.name,
            '--label', 'org.platform-signal.idp-owner=' + self.generation,
            '--memory=768m', '--cpus=1', '--pids-limit=256', '--ulimit', 'nofile=4096:4096',
            '--read-only', '--tmpfs', '/tmp:size=128m,mode=1777',
            '--tmpfs', '/opt/keycloak/data:size=128m,uid=1000,gid=0,mode=0700',
            '--mount', 'type=bind,source=' + str(certs) + ',target=/fixtures,readonly',
            '--mount', 'type=bind,source=' + str(imports) + ',target=/opt/keycloak/data/import,readonly',
            '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1',
            '-p', '127.0.0.1:' + str(port) + ':8443', '-e', 'JAVA_OPTS_KC_HEAP=-Xms64m -Xmx512m',
            prepared, 'start', '--optimized', '--cache=local', '--import-realm', '--http-enabled=false',
            '--hostname=' + origin, '--https-certificate-file=/fixtures/leaf.pem',
            '--https-certificate-key-file=/fixtures/leaf.key'], timeout=30)
        context = ssl.create_default_context(cafile=str(certs / 'root.pem'))
        # No ambient proxies; exact local HTTPS and authenticated issuer.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            state = json.loads(self.command(['docker', 'inspect', '--format', '{{json .State}}', self.name]))
            if not state['Running']:
                (self.output / 'provider.log').write_text(self.command(['docker', 'logs', self.name]))
                raise RuntimeError('provider exited before discovery')
            try:
                metadata = discovery(opener, issuer + '/.well-known/openid-configuration',
                                     min(2, max(0.001, deadline - time.monotonic())))
                if metadata.get('issuer') != issuer:
                    raise ValueError('discovery byte/issuer contract')
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            raise TimeoutError('provider discovery deadline')
        self.stage = 'provider-ready'
        if args.provider_only:
            return {'checks': ['established-provider-https-discovery'], 'provider_image': image,
                    'provider_prepared_image_id': prepared, 'issuer': issuer}
        if args.browser_path is None:
            args.browser_path = Path(self.command(['node', '-e',
                "process.stdout.write(require('./tools/identity/node_modules/playwright-core').chromium.executablePath())"]))
        if not args.browser_path.is_file() or not args.binary.is_file():
            raise ValueError('real browser and server binary paths required')
        self.stage = 'server-start'
        ca = ssl.PEM_cert_to_DER_cert((certs / 'root.pem').read_text())
        identity = scratch / 'identity.json'
        private_json(identity, {'schema_version': 1,
            'endpoint': issuer + '/protocol/openid-connect/token/introspect', 'client_id': 'signal-fixture',
            'issuer': issuer, 'audience': 'signal', 'lease_seconds': 5,
            'workers': 2, 'request_timeout_ms': 1000,
            'roots_der_base64': [base64.b64encode(ca).decode()], 'policy': policy(issuer)})
        rules = scratch / 'rules'; rules.mkdir()
        (rules / 'synthetic.yaml').write_text('apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: synthetic.idp\n  name: Synthetic identity fixture\nspec:\n  severity: high\n  match:\n    all:\n      - field: source.type\n        eq: synthetic-idp\n  finding:\n    title: Synthetic identity security event\n')
        server_config = scratch / 'server.yaml'
        server_config.write_text('schema_version: 1\nrules:\n  directories:\n    - ' + json.dumps(str(rules)) + '\n')
        environment = {k: v for k, v in os.environ.items() if not k.startswith('SIGNAL_')}
        environment.update(SIGNAL_LISTEN='127.0.0.1:0', SIGNAL_ACCESS_CONFIG=str(identity),
            SIGNAL_IDENTITY_CLIENT_SECRET=secrets['signal-fixture'], SIGNAL_CONFIG=str(server_config),
            SIGNAL_WAL_DIR=str(scratch / 'wal'), SIGNAL_STORAGE_DIR=str(scratch / 'events'),
            SIGNAL_FINDINGS_DIR=str(scratch / 'findings'), SIGNAL_STORAGE_FLUSH_MS='10',
            SIGNAL_REQUEST_TIMEOUT_MS='500', SIGNAL_QUERY_TIMEOUT_MS='500', SIGNAL_SHUTDOWN_TIMEOUT_MS='1500')
        server = self.owner.spawn([str(args.binary.resolve())], environment, 'server')
        server_origin = None
        server_ready = False
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.owner.check()
            if self.owner.exited(server) is not None:
                raise RuntimeError('server exited before readiness')
            path = self.output / 'server.log'
            if path.exists():
                for line in OWN.log_text(path).splitlines():
                    try:
                        address = json.loads(line).get('fields', {}).get('listen')
                    except ValueError:
                        continue
                    if address:
                        server_origin = 'http://' + address
                        break
            if server_origin:
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                        server_origin + '/readyz', timeout=1) as reply:
                    if reply.status == 200:
                        server_ready = True
                        break
            time.sleep(0.02)
        if not server_ready:
            raise TimeoutError('server readiness deadline')
        self.stage = 'browser-start'
        leaf_pub = self.command(['openssl', 'x509', '-in', str(certs / 'leaf.pem'), '-pubkey', '-noout'])
        # Conversion input contains only a public key, never credentials.
        pub = scratch / 'leaf-public.pem'; pub.write_text(leaf_pub)
        der = scratch / 'leaf-public.der'
        self.command(['openssl', 'pkey', '-pubin', '-in', str(pub), '-outform', 'DER', '-out', str(der)])
        spki = base64.b64encode(hashlib.sha256(der.read_bytes()).digest()).decode()
        profile = scratch / 'browser'; profile.mkdir()
        browser = self.owner.spawn([str(args.browser_path.resolve()), '--headless', '--no-sandbox',
            '--disable-background-networking', '--disable-breakpad', '--disable-crash-reporter',
            '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
            '--ignore-certificate-errors-spki-list=' + spki, '--user-data-dir=' + str(profile), 'about:blank'],
            environment, 'browser')
        deadline = time.monotonic() + 10
        while not (profile / 'DevToolsActivePort').exists():
            self.owner.check()
            if self.owner.exited(browser) is not None or time.monotonic() >= deadline:
                raise RuntimeError('owned browser startup failed')
            time.sleep(0.02)
        debug_port = int((profile / 'DevToolsActivePort').read_text().splitlines()[0])
        config = scratch / 'browser-config.json'
        browser_report = scratch / 'browser-report.json'
        private_json(config, {'issuer': issuer, 'callback': callback, 'server_origin': server_origin,
            'debug_url': 'http://127.0.0.1:' + str(debug_port), 'secrets': secrets, 'subjects': SUBJECTS,
            'certs': str(certs), 'scratch': str(scratch), 'report': str(browser_report)})
        self.stage = 'oidc-browser-flow'
        sdk = self.owner.spawn(['node', str(ROOT / 'scripts/check-access-idp-browser.cjs'), '--config', str(config)],
            environment, 'oidc-client')
        completed_controls = set()
        deadline = time.monotonic() + 100
        while self.owner.exited(sdk) is None:
            self.owner.check()
            if time.monotonic() >= deadline:
                raise TimeoutError('OIDC browser/client deadline')
            for operation in ('pause', 'unpause'):
                request = scratch / ('control-' + operation)
                if request.exists() and operation not in completed_controls:
                    if request.is_symlink() or request.stat().st_size != 0:
                        raise ValueError('provider control contract')
                    self.control(operation)
                    completed_controls.add(operation)
                    (scratch / ('ack-' + operation)).touch(exist_ok=False)
            time.sleep(0.02)
        if self.owner.stop(sdk) != 0 or not browser_report.is_file() or browser_report.stat().st_size > 65536:
            raise RuntimeError('OIDC client qualification failed')
        browser_result = json.loads(browser_report.read_text())
        if browser_result.get('status') != 'passed_simulated' or completed_controls != {'pause', 'unpause'}:
            raise RuntimeError('OIDC browser/control qualification incomplete')
        self.stage = 'qualified'
        for log in self.owner.logs:
            raw = OWN.log_text(log)
            if any(secret in raw for secret in secrets.values()):
                raise RuntimeError('synthetic credential leaked to process log')
        return {'checks': browser_result['checks'], 'provider_image': image,
            'provider_prepared_image_id': prepared, 'issuer': issuer,
            'server_binary_sha256': NATIVE.sha256(args.binary), 'browser_sha256': NATIVE.sha256(args.browser_path),
            'browser': browser_result['browser'], 'protocol_client': browser_result['protocol_client']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/debug/signal-server')
    parser.add_argument('--browser-path', type=Path)
    parser.add_argument('--provider-only', action='store_true')
    args = parser.parse_args(argv)
    output = args.output.resolve()
    run = Run(output)
    report = {'schema_version': 1, 'status': 'running', 'scope': 'local established IdP; not live tenant/cloud/native qualification',
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'provider_image_reference': IMAGE}
    error = None
    try:
        # Never place credential mounts under uploadable qualification artifacts.
        scratch = Path(tempfile.mkdtemp(prefix='signal-idp-'))
        try:
            report.update(run.execute(args, scratch))
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            # Uncertain ownership/cleanup must retain private mounts for recovery.
            try:
                run.cleanup()
            except Exception as exc:
                run.cleanup_errors.append('cleanup coordinator: ' + type(exc).__name__)
            if run.cleanup_errors:
                report['private_recovery'] = {'scratch': str(scratch), 'container': run.name,
                    'image': run.image_name, 'owner_generation': run.generation}
            else:
                shutil.rmtree(scratch)
        if run.cleanup_errors:
            raise RuntimeError('owned resource cleanup failed')
        report['status'] = 'passed_provider_only' if args.provider_only else 'passed_simulated'
    except (Exception, KeyboardInterrupt) as exc:
        error = exc
        report.update(status='failed', error_type=type(exc).__name__, failed_stage=run.stage)
    report['cleanup_errors'] = [str(e)[:256] for e in run.cleanup_errors]
    report['completed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'stage': run.stage, 'report': str(output / 'qualification.json')}))
    return 1 if error else 0


if __name__ == '__main__':
    def interrupted(kind, _frame):
        raise KeyboardInterrupt('owned local IdP gate interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())

#!/usr/bin/env python3
"""Finite actual mTLS monolith/agent, denial, retained spool and restart rotation.

All generated CA/private material stays in a private disposable scratch root,
outside retained qualification artifacts. No ambient credentials/cloud authority.
"""
import argparse
import base64
import datetime
import hashlib
import http.client
import importlib.util
import itertools
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import struct
import tempfile
import time
import traceback
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('signal_transport_owner', ROOT / 'scripts/check-access-idp.py')
HELP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELP)


def absolute_request(context, port, path, token, timeout=1, method='GET', body=None):
    """One absolute Linux main-thread budget includes handshake/headers/body."""
    def expired(_kind, _frame):
        raise TimeoutError('transport fixture request deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=timeout, context=context)
    try:
        headers = {'Content-Type': 'application/json'}
        if token is not None:
            headers['Authorization'] = 'Bearer ' + token
        connection.request(method, path, body=body, headers=headers)
        reply = connection.getresponse()
        raw = reply.read(262145)
        if len(raw) > 262144:
            raise RuntimeError('transport fixture response capacity')
        return reply.status, raw
    finally:
        connection.close()
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class Run:
    def __init__(self, server, agent, output):
        if output.exists():
            raise ValueError('fresh transport output required')
        # Resolve local socket availability before creating private material.
        self.port, self.metrics_port = HELP.free_port(), HELP.free_port()
        output.mkdir(parents=True, mode=0o700)
        self.output, self.server_binary, self.agent_binary = output, server, agent
        self.private = Path(tempfile.mkdtemp(prefix='signal-transport-private-'))
        self.owners, self.checks, self.cleanup_errors = [], [], []
        self.server = self.server_owner = None
        self.token = 'synthetic-transport-token-a'
        self.environment = {k: v for k, v in os.environ.items() if not k.startswith('SIGNAL_')}
        self.command_count = 0

    def openssl(self, *args):
        self.command_count += 1
        if self.command_count > 100:
            raise RuntimeError('certificate command capacity')
        with (self.output / 'certificate-commands.log').open('ab') as log:
            HELP.NATIVE.run_bounded(['openssl', *map(str, args)], log, timeout=5, grace=0.05)
        if (self.output / 'certificate-commands.log').stat().st_size > 65536:
            raise RuntimeError('certificate log capacity')

    def ca(self, name):
        directory = self.private / name
        directory.mkdir()
        (directory / 'index').write_text('')
        (directory / 'serial').write_text('10\n')
        (directory / 'crlnumber').write_text('10\n')
        config = directory / 'ca.conf'
        config.write_text(f'''[ca]
default_ca=local
[local]
database={directory}/index
serial={directory}/serial
crlnumber={directory}/crlnumber
new_certs_dir={directory}
certificate={directory}/ca.pem
private_key={directory}/ca.key
default_md=sha256
default_days=1
default_crl_days=1
unique_subject=no
policy=policy
[policy]
commonName=supplied
''')
        self.openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-noenc', '-keyout', directory / 'ca.key', '-out', directory / 'ca.pem', '-days', '2',
            '-subj', '/CN=synthetic-' + name, '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        return directory

    def leaf(self, ca, name, usage, expired=False, wrong_name=False):
        prefix = ca / name
        self.openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
            '-keyout', prefix.with_suffix('.key'), '-out', prefix.with_suffix('.csr'),
            '-subj', '/CN=synthetic-' + name)
        extensions = prefix.with_suffix('.ext')
        extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
            + 'extendedKeyUsage=' + usage + '\n'
            + ('subjectAltName=DNS:wrong.example.test\n' if wrong_name else 'subjectAltName=IP:127.0.0.1,DNS:localhost\n'))
        args = ['ca', '-batch', '-config', ca / 'ca.conf', '-in', prefix.with_suffix('.csr'),
                '-out', prefix.with_suffix('.pem'), '-notext', '-extfile', extensions]
        if expired:
            now = datetime.datetime.now(datetime.timezone.utc)
            args += ['-startdate', (now - datetime.timedelta(days=2)).strftime('%Y%m%d%H%M%SZ'),
                     '-enddate', (now - datetime.timedelta(days=1)).strftime('%Y%m%d%H%M%SZ')]
        self.openssl(*args)
        self.openssl('pkcs8', '-topk8', '-nocrypt', '-in', prefix.with_suffix('.key'),
                     '-outform', 'DER', '-out', prefix.with_suffix('.der-key'))
        return prefix

    def crl(self, ca, name, revoke=None):
        if revoke is not None:
            self.openssl('ca', '-batch', '-config', ca / 'ca.conf', '-revoke', revoke.with_suffix('.pem'))
        pem, der = ca / (name + '.crl-pem'), ca / (name + '.crl-der')
        self.openssl('ca', '-gencrl', '-config', ca / 'ca.conf', '-out', pem)
        self.openssl('crl', '-in', pem, '-outform', 'DER', '-out', der)
        return der

    def material(self, name, leaf, roots, crls=()):
        def cert(path):
            return base64.b64encode(ssl.PEM_cert_to_DER_cert(path.read_text())).decode()
        path = self.private / (name + '.json')
        HELP.private_json(path, {'schema_version': 1,
            'certificate_chain_der_base64': [cert(leaf.with_suffix('.pem'))],
            'private_key_der_base64': base64.b64encode(leaf.with_suffix('.der-key').read_bytes()).decode(),
            'peer_roots_der_base64': [cert(root / 'ca.pem') for root in roots],
            'peer_crls_der_base64': [base64.b64encode(crl.read_bytes()).decode() for crl in crls]})
        return path

    def context(self, root, leaf=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(root / 'ca.pem')
        if leaf is not None:
            context.load_cert_chain(leaf.with_suffix('.pem'), leaf.with_suffix('.key'))
        return context

    def owner(self, name):
        if len(self.owners) >= 24:
            raise RuntimeError('transport owner capacity')
        directory = self.output / name
        directory.mkdir()
        owner = HELP.OwnedGroups(directory)
        self.owners.append(owner)
        return owner

    def wait(self, predicate, description, budget=10):
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        raise RuntimeError(description)

    def start_server(self, material, context, name):
        owner = self.owner(name)
        env = dict(self.environment, SIGNAL_LISTEN=f'127.0.0.1:{self.port}',
            SIGNAL_METRICS_LISTEN=f'127.0.0.1:{self.metrics_port}', SIGNAL_API_TOKEN=self.token,
            SIGNAL_TLS_CONFIG=str(material), SIGNAL_WAL_DIR=str(self.private / 'wal'),
            SIGNAL_STORAGE_DIR=str(self.private / 'events'), SIGNAL_FINDINGS_DIR=str(self.private / 'findings'),
            SIGNAL_STORAGE_FLUSH_MS='10', SIGNAL_REQUEST_TIMEOUT_MS='250',
            SIGNAL_CONNECTION_TIMEOUT_MS='1000', SIGNAL_SHUTDOWN_TIMEOUT_MS='1500', SIGNAL_MAX_CONNECTIONS='4')
        self.server_owner = owner
        self.trusted_context = context
        self.server = owner.spawn([str(self.server_binary)], env, 'server')
        def ready():
            if owner.exited(self.server) is not None:
                raise RuntimeError('transport server exited before readiness')
            try:
                return absolute_request(context, self.port, '/readyz', self.token)[0] == 200
            except (OSError, http.client.HTTPException):
                return False
        self.wait(ready, 'transport server readiness deadline')

    def stop_server(self):
        if self.server is not None:
            assert self.server_owner.stop(self.server) == 0, 'transport graceful server shutdown'
            self.server = None

    def rows(self, context, source):
        status, raw = absolute_request(context, self.port, '/v1/events?' + urllib.parse.urlencode({'source': source, 'limit': 10}), self.token)
        assert status == 200, 'transport query denied'
        return json.loads(raw)['events']

    def agent(self, name, material, source, host='127.0.0.1', token=None, invalid=False):
        owner = self.owner(name)
        source_file = self.private / (source + '.log')
        if not source_file.exists():
            source_file.write_text('synthetic transport ' + source + '\n')
        spool = self.private / ('spool-' + source)
        env = dict(self.environment, SIGNAL_AGENT_API_TOKEN=token or self.token,
                   SIGNAL_AGENT_TLS_CONFIG=str(material))
        child = owner.spawn([str(self.agent_binary), '--server', f'https://{host}:{self.port}',
            '--spool-dir', str(spool), '--file', str(source_file), '--once', '--source-type', source,
            '--flush-ms', '10', '--request-timeout-ms', '400', '--shutdown-timeout-ms', '900',
            '--retry-base-ms', '20', '--retry-max-ms', '50'], env, 'agent')
        self.wait(lambda: owner.exited(child) is not None, 'transport agent exit deadline', 8)
        code = owner.stop(child)
        if invalid:
            assert code != 0 and not spool.exists(), 'invalid private configuration mutated spool'
            return []
        records = list(itertools.islice(spool.glob('record-*'), 2))
        if code == 0:
            assert not records, 'successful transport left pending spool'
            return []
        assert code != 0 and len(records) == 1, 'uncertain transport did not retain exactly one spool record'
        with records[0].open('rb') as stream:
            data = stream.read(65537)
        assert 12 < len(data) <= 65536, 'bounded retained spool record'
        length = struct.unpack('<I', data[:4])[0]
        assert length == len(data) - 12, 'retained spool frame length'
        return [json.loads(data[12:])['event']['id']]

    def deny(self, context, path='/readyz', port=None, server_trust_changed=False):
        denied = False
        try:
            absolute_request(context, port or self.port, path, self.token)
        except (ConnectionResetError, ssl.SSLEOFError):
            denied = True
        except ssl.SSLError as exc:
            # Timeout, refused connection and malformed HTTP are failures,
            # never peer-denial evidence. Only authenticated TLS alerts count.
            allowed = {
                'TLSV13_ALERT_CERTIFICATE_REQUIRED', 'SSLV3_ALERT_BAD_CERTIFICATE',
                'SSLV3_ALERT_CERTIFICATE_EXPIRED', 'SSLV3_ALERT_CERTIFICATE_UNKNOWN',
                'SSLV3_ALERT_CERTIFICATE_REVOKED', 'TLSV1_ALERT_UNKNOWN_CA',
                'SSLV3_ALERT_HANDSHAKE_FAILURE', 'TLSV1_ALERT_ACCESS_DENIED',
            }
            if server_trust_changed:
                allowed.add('CERTIFICATE_VERIFY_FAILED')
            assert exc.reason in allowed, 'unexpected TLS denial reason'
            denied = True
        assert denied, 'untrusted transport reached HTTP'
        selected_port = port or self.port
        live_path = '/metrics' if selected_port == self.metrics_port else '/readyz'
        assert absolute_request(self.trusted_context, selected_port, live_path, self.token)[0] == 200, 'trusted same-listener liveness after TLS denial'

    def mark(self, name):
        for owner in self.owners:
            owner.check()
        self.checks.append(name)

    def qualify(self):
        ca, foreign, rotated = self.ca('original'), self.ca('foreign'), self.ca('rotated')
        server = self.leaf(ca, 'server', 'serverAuth')
        client = self.leaf(ca, 'client', 'clientAuth')
        old_client = self.leaf(ca, 'revoked', 'clientAuth')
        expired_client = self.leaf(ca, 'expired', 'clientAuth', expired=True)
        foreign_client = self.leaf(foreign, 'client', 'clientAuth')
        rotated_server = self.leaf(rotated, 'server', 'serverAuth')
        rotated_client = self.leaf(rotated, 'client', 'clientAuth')
        wrong_server = self.leaf(ca, 'wrong-server', 'serverAuth', wrong_name=True)
        expired_server = self.leaf(ca, 'expired-server', 'serverAuth', expired=True)
        ca_crl, rotated_crl = self.crl(ca, 'clean'), self.crl(rotated, 'clean')
        server_config = self.material('server', server, [ca], [ca_crl])
        client_config = self.material('client', client, [ca], [ca_crl])
        old_config = self.material('old-client', old_client, [ca], [ca_crl])
        wrong_root_config = self.material('wrong-root', client, [foreign])
        context = self.context(ca, client)
        self.start_server(server_config, context, 'initial-server')
        assert not self.agent('valid-agent', client_config, 'valid-mtls', host='localhost')
        self.wait(lambda: len(self.rows(context, 'valid-mtls')) == 1, 'actual mTLS persistence')
        original_ids = {row['id'] for row in self.rows(context, 'valid-mtls')}
        self.mark('actual_named_endpoint_agent_mtls_wal_parquet_query')
        assert absolute_request(context, self.port, '/v1/events', None)[0] == 401
        assert absolute_request(context, self.port, '/v1/events', 'wrong-token')[0] == 401
        assert absolute_request(context, self.metrics_port, '/metrics', self.token)[0] == 200
        self.mark('tls_peer_requires_independent_api_authorization_and_metrics_mtls')
        for label, peer in [('missing', None), ('foreign', foreign_client), ('expired', expired_client)]:
            self.deny(self.context(ca, peer))
            self.deny(self.context(ca, peer), port=self.metrics_port)
            self.mark(label + '_peer_denied_on_both_listeners')
        with socket.create_connection(('127.0.0.1', self.port), timeout=1) as sock:
            sock.settimeout(1)
            sock.sendall(b'GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n')
            try:
                reply = sock.recv(1024)
            except ConnectionResetError:
                reply = b''
            assert not reply.startswith(b'HTTP/'), 'plaintext fallback'
        self.mark('selected_tls_plaintext_denied')
        ids = self.agent('wrong-root-agent', wrong_root_config, 'retained-root')
        assert len(ids) == 1 and not self.rows(context, 'retained-root')
        assert not self.agent('correct-root-replay', client_config, 'retained-root')
        self.wait(lambda: {row['id'] for row in self.rows(context, 'retained-root')} == set(ids), 'retained original IDs replay')
        self.mark('wrong_server_root_retains_original_spool_and_exact_id_replay')
        bad = self.private / 'malformed.json'
        HELP.private_json(bad, {'schema_version': 1, 'private_key_der_base64': 'synthetic-private-canary'})
        self.agent('malformed-agent', bad, 'no-mutation', invalid=True)
        self.mark('private_input_denied_before_agent_source_spool_mutation')
        # Silent TLS peers consume the same bounded physical connection slots.
        silent = []
        try:
            for _ in range(3):
                sock = socket.create_connection(('127.0.0.1', self.port), timeout=1)
                sock.settimeout(1)
                silent.append(sock)
            time.sleep(0.35)
            for sock in silent:
                assert sock.recv(1) == b'', 'silent handshake outlived original deadline'
            assert absolute_request(context, self.port, '/readyz', self.token)[0] == 200
            self.mark('silent_handshake_slots_retire_and_authenticated_admission_recovers')
        finally:
            for sock in silent:
                sock.close()
        self.stop_server()
        for label, leaf in [('hostname', wrong_server), ('server-expiry', expired_server)]:
            material = self.material(label, leaf, [ca], [ca_crl])
            # The fixture cannot use a bypassing ready check: observe listener
            # startup over TCP only, then prove the actual agent rejects its peer.
            owner = self.owner(label + '-server')
            env = dict(self.environment, SIGNAL_LISTEN=f'127.0.0.1:{self.port}', SIGNAL_API_TOKEN=self.token,
                SIGNAL_TLS_CONFIG=str(material), SIGNAL_WAL_DIR=str(self.private / 'wal'),
                SIGNAL_STORAGE_DIR=str(self.private / 'events'), SIGNAL_FINDINGS_DIR=str(self.private / 'findings'),
                SIGNAL_STORAGE_FLUSH_MS='10')
            self.server_owner, self.server = owner, owner.spawn([str(self.server_binary)], env, 'server')
            def listening():
                if owner.exited(self.server) is not None:
                    raise RuntimeError('invalid-peer server startup failed')
                try:
                    with socket.create_connection(('127.0.0.1', self.port), timeout=0.2):
                        return True
                except OSError:
                    return False
            self.wait(listening, 'invalid-peer server listener startup')
            retained = self.agent(label + '-agent', client_config, label)
            assert len(retained) == 1
            self.stop_server()
            self.start_server(server_config, context, label + '-recovery-server')
            assert not self.rows(context, label), 'untrusted server admitted an uncertain event before replay'
            assert not self.agent(label + '-replay', client_config, label)
            self.wait(lambda: {r['id'] for r in self.rows(context, label)} == set(retained), 'invalid-server retained ID recovery')
            self.mark(label + '_denial_and_original_spool_recovery')
            self.stop_server()
        revoked_crl = self.crl(ca, 'revoked', old_client)
        revoked_server = self.material('revoked-server', server, [ca], [revoked_crl])
        self.start_server(revoked_server, context, 'revocation-server')
        self.deny(self.context(ca, old_client))
        retained = self.agent('revoked-agent', old_config, 'revoked-recovery')
        assert len(retained) == 1 and not self.rows(context, 'revoked-recovery')
        assert not self.agent('revoked-identity-replacement', client_config, 'revoked-recovery')
        self.wait(lambda: {r['id'] for r in self.rows(context, 'revoked-recovery')} == set(retained), 'revoked identity replacement retained IDs')
        self.mark('signed_crl_denies_revoked_peer_and_replacement_replays_original_ids')
        self.stop_server()
        self.token = 'synthetic-transport-token-b'
        new_server = self.material('rotated-server', rotated_server, [rotated], [rotated_crl])
        new_client = self.material('rotated-client', rotated_client, [rotated], [rotated_crl])
        new_context = self.context(rotated, rotated_client)
        self.start_server(new_server, new_context, 'rotated-server')
        self.deny(context, server_trust_changed=True)
        retained = self.agent('old-roots-agent', client_config, 'rotated-recovery', token='synthetic-transport-token-a')
        assert len(retained) == 1
        assert not self.rows(new_context, 'rotated-recovery'), 'old authority admitted event after rotation'
        assert absolute_request(new_context, self.port, '/v1/events', 'synthetic-transport-token-a')[0] == 401
        assert not self.agent('rotated-agent-replay', new_client, 'rotated-recovery')
        self.wait(lambda: {r['id'] for r in self.rows(new_context, 'rotated-recovery')} == set(retained), 'rotated authority retained ID recovery')
        assert {row['id'] for row in self.rows(new_context, 'valid-mtls')} == original_ids
        self.mark('stopped_restart_root_certificate_token_rotation_preserves_wal_storage_and_spool_ids')
        # A peer that drips a partial TLS record cannot restart the original
        # handshake clock. Shutdown also owns sockets still in TLS admission.
        with socket.create_connection(('127.0.0.1', self.port), timeout=1) as trickle:
            trickle.settimeout(0.01)
            began = time.monotonic()
            trickle.sendall(b'\x16\x03\x03\x00\x64')  # Valid 100-byte record, body incomplete.
            observed_active, closed = False, False
            for _ in range(12):
                try:
                    trickle.sendall(b'\x01')
                except (BrokenPipeError, ConnectionResetError):
                    closed = True
                    break
                time.sleep(0.03)
                try:
                    reply = trickle.recv(1, socket.MSG_PEEK)
                    assert reply == b'', 'incomplete TLS record elicited protocol data'
                    closed = True
                    break
                except socket.timeout:
                    observed_active |= time.monotonic() - began >= 0.12
                except ConnectionResetError:
                    closed = True
                    break
            assert observed_active, 'trickle was rejected instead of holding a live handshake'
            assert closed and time.monotonic() - began < 0.35, 'trickling handshake exceeded 250ms budget plus scheduling allowance'
        assert absolute_request(new_context, self.port, '/readyz', self.token)[0] == 200
        self.mark('trickling_handshake_cannot_extend_original_deadline')
        active = []
        try:
            for _ in range(2):
                sock = socket.create_connection(('127.0.0.1', self.port), timeout=1)
                sock.settimeout(0.03)
                sock.sendall(b'\x16\x03\x03\x00\x64')
                active.append(sock)
            time.sleep(0.04)
            for sock in active:
                try:
                    sock.recv(1, socket.MSG_PEEK)
                except socket.timeout:
                    pass
                else:
                    raise AssertionError('peer was not still active before shutdown')
                sock.settimeout(1)
            began = time.monotonic()
            self.stop_server()
            assert time.monotonic() - began < 1.7, 'active TLS shutdown exceeded 1500ms budget plus scheduling allowance'
            for sock in active:
                try:
                    assert sock.recv(1) == b'', 'shutdown left an active TLS peer'
                except ConnectionResetError:
                    pass
            self.mark('cancellation_shutdown_retires_active_tls_peers_and_process_owner')
        finally:
            for sock in active:
                sock.close()
        # No credentials/material can enter public retained process logs.
        canaries = [self.token, 'synthetic-transport-token-a', 'synthetic-private-canary', 'BEGIN PRIVATE KEY']
        for owner in self.owners:
            for path in owner.logs:
                with path.open('rb') as stream:
                    data = stream.read(1048577)
                assert len(data) <= 1024 * 1024
                assert not any(value.encode() in data for value in canaries), 'private transport diagnostic leakage'
        self.mark('secret_free_bounded_process_diagnostics_and_owned_cleanup')

    def cleanup(self):
        for owner in reversed(self.owners):
            try:
                self.cleanup_errors.extend(owner.cleanup())
            except BaseException as exc:
                self.cleanup_errors.append('owned transport cleanup: ' + type(exc).__name__)
        if not self.cleanup_errors:
            shutil.rmtree(self.private)
        else:
            self.cleanup_errors.append('private scratch retained for owned process recovery')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('server', type=Path)
    parser.add_argument('agent', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    run = Run(args.server.resolve(), args.agent.resolve(), args.output.resolve())
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    def interrupted(_kind, _frame):
        raise KeyboardInterrupt('transport qualification interrupted')
    previous = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGINT)}
    failure = None
    failure_site = None
    try:
        run.qualify()
    except BaseException as exc:
        failure = type(exc).__name__  # Never persist exception values/private paths.
        last = traceback.extract_tb(exc.__traceback__)[-1]
        failure_site = {'file': Path(last.filename).name, 'line': last.lineno, 'function': last.name}
    finally:
        # Repeated interruption cannot skip remaining owned process cleanup.
        for kind in previous:
            signal.signal(kind, signal.SIG_IGN)
        run.cleanup()
        for kind, handler in previous.items():
            signal.signal(kind, handler)
        report = {'schema_version': 1, 'status': 'passed_simulated' if failure is None and not run.cleanup_errors else 'failed',
            'started_at': started, 'completed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'checks': run.checks, 'failure_type': failure, 'failure_site': failure_site, 'cleanup_errors': run.cleanup_errors,
            'server_sha256': HELP.NATIVE.sha256(run.server_binary), 'agent_sha256': HELP.NATIVE.sha256(run.agent_binary),
            'limits': {'owners': 24, 'leaders_per_owner': 3, 'logs_per_owner': 8, 'log_bytes': 1048576,
                       'certificate_commands': 100, 'command_seconds': 5, 'response_bytes': 262144},
            'qualification': 'Actual local TLS/process simulation; no AWS, ARM64, remote CI, production PKI or power-loss proof.'}
        (run.output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    if report['status'] != 'passed_simulated':
        print('Transport server gate failed: ' + str(failure))
        return 1
    print('Transport server gate passed: ' + str(len(run.checks)) + ' compound checks')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

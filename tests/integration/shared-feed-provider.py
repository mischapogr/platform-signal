#!/usr/bin/env python3
"""Owned finite TLS introspection service for the native shared HTTP test."""
import base64
import argparse
import http.server
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('signal_access_fixture', ROOT / 'tests/integration/access-server-process.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--custody-only',action='store_true')
    args=parser.parse_args()
    path = Path(os.environ['SIGNAL_CONTROL_FIXTURE'])
    if path.stat().st_size > 4096:
        raise ValueError('fixture byte capacity')
    certs = Path(json.loads(path.read_text())['root_der']).parent
    counters = {'calls': 0, 'invalid': 0}
    if args.custody_only:
        def openssl(*argv):
            subprocess.run(['openssl',*map(str,argv)],timeout=5,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-noenc','-keyout',certs/'custody-client.key','-out',certs/'custody-client.csr','-subj','/CN=synthetic-custody-producer')
        (certs/'custody-client.ext').write_text('keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
        openssl('x509','-req','-in',certs/'custody-client.csr','-CA',certs/'root.pem','-CAkey',certs/'root.key','-set_serial','3','-days','1','-extfile',certs/'custody-client.ext','-out',certs/'custody-client.pem')
        for name in ('leaf','custody-client'):
            openssl('x509','-in',certs/(name+'.pem'),'-outform','DER','-out',certs/(name+'.der'))
            openssl('pkcs8','-topk8','-nocrypt','-in',certs/(name+'.key'),'-outform','DER','-out',certs/(name+'-key.der'))
            material={'schema_version':1,'certificate_chain_der_base64':[base64.b64encode((certs/(name+'.der')).read_bytes()).decode()],
                      'private_key_der_base64':base64.b64encode((certs/(name+'-key.der')).read_bytes()).decode(),
                      'peer_roots_der_base64':[base64.b64encode((certs/'root.der').read_bytes()).decode()]}
            output=certs/(name+'-tls.json');output.write_text(json.dumps(material));output.chmod(0o600)
        for name in ('custody-client.key','custody-client-key.der','leaf-key.der'):
            (certs/name).chmod(0o600)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            self.connection.settimeout(1)
            counters['calls'] += 1
            length = int(self.headers.get('Content-Length', '0'))
            expected = 'Basic ' + base64.b64encode(b'synthetic-client:synthetic-shared-feed-secret').decode()
            if (counters['calls'] > 64 or self.path != '/token' or not 0 < length <= 16384
                    or self.headers.get('Authorization') != expected):
                counters['invalid'] += 1
                self.send_error(400)
                return
            fields = urllib.parse.parse_qs(self.rfile.read(length).decode())
            if fields.get('token_type_hint') != ['access_token']:
                counters['invalid'] += 1
                self.send_error(400)
                return
            token = fields.get('token', [''])[0]
            payload = {'active': token != 'inactive', 'iss': 'https://identity.example.test',
                       'sub': 'reader' if token == 'expired' else (('custodian' if args.custody_only else 'producer') if token == 'short' else token), 'aud': 'signal',
                       'exp': int(time.time()) + (-1 if token == 'expired' else (2 if token == 'short' else 60)),
                       'token_type': 'Bearer', 'roles': ['reader'], 'scope': 'admin'}
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certs / 'leaf.pem', certs / 'leaf.key')
    provider = fixture.FiniteTLSProvider(('127.0.0.1', 0), Handler, context)
    thread = threading.Thread(target=provider.serve_forever, kwargs={'poll_interval': 0.05})
    try:
        fixture.start_provider_thread(thread)
        environment = os.environ.copy()
        environment['SIGNAL_SHARED_HTTP_PROVIDER'] = f'https://127.0.0.1:{provider.server_port}/token'
        if args.custody_only:
            environment['SIGNAL_CUSTODY_SERVER_TLS']=str(certs/'leaf-tls.json')
            environment['SIGNAL_CUSTODY_CLIENT_TLS']=str(certs/'custody-client-tls.json')
            result=subprocess.run(['cargo','test','--locked','--offline','-p','signal-server','--features','s3-query','--test','shared',
                                   'custody::runtime::postgres_tls_s3_configured_custody','--','--ignored','--exact','--nocapture'],cwd=ROOT,env=environment,timeout=55,check=False)
            if result.returncode or not 5<=counters['calls']<=64 or counters['invalid']:
                raise RuntimeError('authenticated custody/provider request qualification failed')
            print('phase: custody-live-TLS-provider-authenticated-peer-producer-qualified')
            return
        result = subprocess.run(['cargo', 'test', '--locked', '--offline', '-p', 'signal-server',
            '--bin', 'signal-server', 'finding_api::shared_http_tests::authorized_shared_feed_http_provider_audit',
            '--', '--ignored', '--exact', '--nocapture'], cwd=ROOT, env=environment, timeout=25, check=False)
        if result.returncode:
            raise RuntimeError('native shared HTTP test failed')
        result = subprocess.run(['cargo', 'test', '--locked', '--offline', '-p', 'signal-server',
            '--test', 'native_shared_admission', 'native_owner_provider_http_wal_admission',
            '--', '--ignored', '--exact', '--nocapture'], cwd=ROOT, env=environment, timeout=15, check=False)
        if result.returncode:
            raise RuntimeError('native owner/provider/HTTP/WAL admission test failed')
        result = subprocess.run(['cargo', 'test', '--locked', '--offline', '-p', 'signal-server',
            '--bin', 'signal-server', 'finding_api::shared_scoped_http_tests::authorized_shared_scoped_http_provider_audit',
            '--', '--ignored', '--exact', '--nocapture'], cwd=ROOT, env=environment, timeout=15, check=False)
        if result.returncode:
            raise RuntimeError('native shared scoped HTTP/provider/audit test failed')
        if not 6 <= counters['calls'] <= 64 or counters['invalid']:
            raise RuntimeError('TLS introspection request contract or count')
    finally:
        fixture.stop_provider(provider, thread)


if __name__ == '__main__':
    main()

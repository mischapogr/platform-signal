#!/usr/bin/env python3
"""Owned finite TLS introspection service for the native shared HTTP test."""
import base64
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
    path = Path(os.environ['SIGNAL_CONTROL_FIXTURE'])
    if path.stat().st_size > 4096:
        raise ValueError('fixture byte capacity')
    certs = Path(json.loads(path.read_text())['root_der']).parent
    counters = {'calls': 0, 'invalid': 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            self.connection.settimeout(1)
            counters['calls'] += 1
            length = int(self.headers.get('Content-Length', '0'))
            expected = 'Basic ' + base64.b64encode(b'synthetic-client:synthetic-shared-feed-secret').decode()
            if (counters['calls'] > 32 or self.path != '/token' or not 0 < length <= 16384
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
                       'sub': 'reader' if token == 'expired' else ('producer' if token == 'short' else token), 'aud': 'signal',
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
        if not 6 <= counters['calls'] <= 32 or counters['invalid']:
            raise RuntimeError('TLS introspection request contract or count')
    finally:
        fixture.stop_provider(provider, thread)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Bounded synthetic loopback dependencies for the owned Standard kind gate."""
import base64
import http.server
import importlib.util
import json
from pathlib import Path
import signal
import ssl
import sys
import threading
import time
import uuid


def initialize(data, document):
    if len(json.dumps(document).encode()) > 512 * 1024 or len(document['files']) > 64:
        raise ValueError('bootstrap capacity')
    for name in ('backend', 'stream'):
        uuid.UUID(document['identity'][name])
    validated = []
    for name, encoded in document['files'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] not in ('wal', 'coverage-root'):
            raise ValueError('bootstrap path outside owned state')
        validated.append((data / path, base64.b64decode(encoded, validate=True)))
    marker = data / 'synthetic-bootstrap.json'
    if marker.exists():
        if json.loads(marker.read_text()) != document['identity']:
            raise ValueError('original PVC ownership mismatch')
        return
    for destination, contents in validated:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            destination.chmod(0o600)
            stream.write(contents)
    marker.write_text(json.dumps(document['identity']))


def main():
    if sys.argv[1:] == ['initialize']:
        document = json.loads(Path('/bootstrap/files.json').read_text())
        initialize(Path('/var/lib/signal'), document)
        return
    config = json.loads(Path('/fixture/config.json').read_text())
    spec = importlib.util.spec_from_file_location('s3_fixture', '/scripts/s3-query-server.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = Path('/var/lib/signal/synthetic-objects')
    root.mkdir(exist_ok=True)
    objects = module.Fixture(root, config['backend_id'], 'signal-fixture', 18081)

    class Identity(http.server.BaseHTTPRequestHandler):
        calls = 0

        def log_message(self, *_args):
            pass

        def do_POST(self):
            self.connection.settimeout(2)
            type(self).calls += 1
            size = int(self.headers.get('Content-Length', '0'))
            expected = 'Basic ' + base64.b64encode(
                b'synthetic-standard:synthetic-standard-idp-secret').decode()
            if self.calls > 512 or self.path != '/token' or not 0 < size <= 16384 or self.headers.get('Authorization') != expected:
                self.send_error(400)
                return
            from urllib.parse import parse_qs
            token = parse_qs(self.rfile.read(size).decode()).get('token', [''])[0]
            body = json.dumps({'active': token in ('global', 'read-a', 'read-b'),
                               'iss': 'https://identity.example.test', 'sub': token,
                               'aud': 'signal', 'exp': int(time.time()) + 60,
                               'token_type': 'Bearer'}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/fixture/leaf.pem', '/fixture/leaf.key')
    class Provider(http.server.HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(2)
            try:
                return context.wrap_socket(connection, server_side=True), address
            except Exception:
                connection.close()
                raise
    identity = Provider(('127.0.0.1', 18082), Identity)
    stopped = threading.Event()
    for kind in (signal.SIGTERM, signal.SIGINT):
        signal.signal(kind, lambda *_: stopped.set())
    threads = [threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .1})
               for server in (objects, identity)]
    try:
        for thread in threads:
            thread.start()
        while not stopped.wait(.2):
            if not all(thread.is_alive() for thread in threads):
                raise RuntimeError('synthetic dependency exited')
    finally:
        for server in (objects, identity):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
            if thread.is_alive():
                raise RuntimeError('synthetic dependency did not stop')


if __name__ == '__main__':
    main()

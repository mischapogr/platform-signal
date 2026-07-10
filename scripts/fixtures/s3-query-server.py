#!/usr/bin/env python3
"""Bounded, persistent, loopback-only S3 query fixture. Never use for production.

One HTTP request at a time; conditional creation, pinned versions, finite pages,
fsync-before-success and explicit faults. SigV4 presence is checked, not validated.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlsplit
import uuid
from xml.sax.saxutils import escape

OBJECT_BYTES = 8 * 1024 * 1024
DISK_BYTES = 64 * 1024 * 1024
OBJECTS = 128
CATALOG_BYTES = 256 * 1024
LOG_BYTES = 1024 * 1024

def read_json(path, maximum):
    with path.open('rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('fixture JSON capacity')
    return json.loads(data)

def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def replace_json(path, value):
    data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    if len(data) > CATALOG_BYTES:
        raise ValueError('fixture catalog capacity')
    temporary = path.with_suffix('.tmp')
    with temporary.open('wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)

class Fixture(HTTPServer):
    allow_reuse_address = True
    def __init__(self, root, fixture_id, bucket, port):
        self.root, self.bucket = root, bucket
        if not root.is_dir() or root.is_symlink():
            raise ValueError('owned fixture directory required')
        marker = root / 'owner.json'
        expected = {'schema_version': 1, 'fixture_id': fixture_id, 'bucket': bucket}
        if marker.exists():
            if read_json(marker, 256) != expected:
                raise ValueError('fixture owner mismatch')
        else:
            if any(root.iterdir()):
                raise ValueError('fresh empty fixture root required')
            replace_json(marker, expected)
            (root / 'objects').mkdir()
            replace_json(root / 'catalog.json', {})
            replace_json(root / 'fault.json', {'mode': 'normal'})
        entries=list((root/'objects').iterdir())
        if len(entries)>OBJECTS or any(p.is_symlink() or not p.is_file() or p.stat().st_size>OBJECT_BYTES for p in entries) or sum(p.stat().st_size for p in entries)>DISK_BYTES:
            raise ValueError('fixture physical inventory capacity')
        self.catalog = read_json(root / 'catalog.json', CATALOG_BYTES)
        if len(self.catalog) > OBJECTS:
            raise ValueError('fixture object capacity')
        for key, meta in self.catalog.items():
            if set(meta) != {'file', 'bytes', 'etag', 'version'} or len(key) > 1024:
                raise ValueError('fixture catalog shape')
            body = root / 'objects' / meta['file']
            if len(meta['file']) != 64 or any(c not in '0123456789abcdef' for c in meta['file']):
                raise ValueError('fixture body identity')
            if body.is_symlink() or body.stat().st_size != meta['bytes'] or meta['bytes'] > OBJECT_BYTES:
                raise ValueError('fixture committed body shape')
            with body.open('rb') as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            if actual != meta['version'] or meta['etag'] != actual:
                raise ValueError('fixture committed body corruption')
        if sum(meta['bytes'] for meta in self.catalog.values()) > DISK_BYTES:
            raise ValueError('fixture disk capacity')
        super().__init__(('127.0.0.1', port), Handler)
    def record(self, method, key, code):
        path = self.root / 'requests.jsonl'
        row = (json.dumps({'method': method, 'key': key, 'status': code}, separators=(',', ':')) + '\n').encode()
        size = path.stat().st_size if path.exists() else 0
        if size + len(row) > LOG_BYTES:
            raise ValueError('fixture request-log capacity')
        with path.open('ab') as stream:
            stream.write(row)
            stream.flush()

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_):
        pass
    def setup(self):
        super().setup()
        self.connection.settimeout(3)
    def response(self, code, body=b'', headers=None):
        self.server.record(self.command, self.path[:2048], code)
        self.send_response(code)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)
        self.close_connection = True
    def error(self, code, name):
        self.response(code, f'<Error><Code>{name}</Code><Message>local fixture</Message></Error>'.encode(), {'Content-Type':'application/xml'})
    def handle_request(self):
        if len(self.path) > 4096 or len(self.headers) > 64 or sum(len(k)+len(v) for k,v in self.headers.items()) > 32768:
            self.error(400, 'InvalidRequest'); return
        if not self.headers.get('Authorization', '').startswith('AWS4-HMAC-SHA256 ') or not self.headers.get('x-amz-date'):
            self.error(403, 'AccessDenied'); return
        parsed = urlsplit(self.path)
        prefix = '/' + self.server.bucket
        if parsed.path != prefix and not parsed.path.startswith(prefix + '/'):
            self.error(403, 'AccessDenied'); return
        query = parse_qs(parsed.query, strict_parsing=True) if parsed.query else {}
        if any(len(v) != 1 for v in query.values()):
            self.error(400, 'InvalidRequest'); return
        key = unquote(parsed.path[len(prefix):].lstrip('/'))
        if len(key) > 1024 or '..' in key.split('/'):
            self.error(400, 'InvalidRequest'); return
        mode = read_json(self.server.root/'fault.json', 256)['mode']
        if mode == 'outage':
            self.connection.shutdown(socket.SHUT_RDWR); self.close_connection = True; return
        if self.command == 'GET' and query.get('list-type') == ['2']:
            if mode == 'deny-list': self.error(403,'AccessDenied'); return
            if mode == 'throttle-list': self.error(429,'SlowDown'); return
            if mode == 'malformed-list': self.response(200,b'<ListBucketResult><invalid',{'Content-Type':'application/xml'}); return
            if mode == 'oversized-control': self.response(200,b'x'*(256*1024+1),{'Content-Type':'application/xml'}); return
            wanted=query.get('prefix',[''])[0]
            entries=sorted(k for k in self.server.catalog if k.startswith(wanted))
            start=int(query.get('continuation-token',['0'])[0]);maximum=min(2,int(query.get('max-keys',['2'])[0]))
            if start<0 or start>len(entries) or maximum<=0: self.error(400,'InvalidRequest');return
            selected=entries[start:start+maximum]; more=start+len(selected)<len(entries)
            items=''.join(f'<Contents><Key>{escape(k)}</Key><LastModified>2026-07-10T18:00:00.000Z</LastModified><ETag>&quot;{self.server.catalog[k]["etag"]}&quot;</ETag><Size>{self.server.catalog[k]["bytes"]}</Size><StorageClass>STANDARD</StorageClass></Contents>' for k in selected)
            token=f'<NextContinuationToken>{start+len(selected)}</NextContinuationToken>' if more else ''
            body=f'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>{escape(self.server.bucket)}</Name><Prefix>{escape(wanted)}</Prefix><KeyCount>{len(selected)}</KeyCount><MaxKeys>{maximum}</MaxKeys><IsTruncated>{str(more).lower()}</IsTruncated>{token}{items}</ListBucketResult>'.encode()
            self.response(200,body,{'Content-Type':'application/xml'});return
        if not key or not key.startswith('query/'):
            self.error(403,'AccessDenied');return
        meta=self.server.catalog.get(key)
        if self.command == 'PUT':
            if self.headers.get('Transfer-Encoding') or not self.headers.get('Content-Length','').isdigit():self.error(400,'InvalidRequest');return
            length=int(self.headers['Content-Length'])
            if length>OBJECT_BYTES:self.error(413,'EntityTooLarge');return
            if self.headers.get('If-None-Match')!='*':self.error(403,'AccessDenied');return
            if meta is not None:self.error(412,'PreconditionFailed');return
            if len(self.server.catalog)>=OBJECTS or sum(m['bytes'] for m in self.server.catalog.values())+length>DISK_BYTES:self.error(507,'InsufficientStorage');return
            body=self.rfile.read(length)
            if len(body)!=length:self.error(400,'IncompleteBody');return
            digest=hashlib.sha256(body).hexdigest(); name=hashlib.sha256(key.encode()).hexdigest(); path=self.server.root/'objects'/name
            if path.exists():
                if path.is_symlink() or path.stat().st_size!=len(body):raise ValueError('uncommitted fixture body conflict')
                with path.open('rb') as stream:
                    existing=stream.read(OBJECT_BYTES+1)
                    if existing!=body:raise ValueError('uncommitted fixture body conflict')
                    os.fsync(stream.fileno())
            else:
                with path.open('xb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
            sync_directory(path.parent)
            meta={'file':name,'bytes':length,'etag':digest,'version':digest}
            next_catalog=dict(self.server.catalog);next_catalog[key]=meta;replace_json(self.server.root/'catalog.json',next_catalog);self.server.catalog=next_catalog
            if mode=='pause-manifest' and '/commits/' in key or mode=='pause-data' and key.endswith('.parquet'):
                replace_json(self.server.root/'effect.json',{'key':key,'version':digest,'stage':'synced_manifest_before_reply' if mode=='pause-manifest' else 'synced_data_before_reply'})
                until=time.monotonic()+3
                while time.monotonic()<until and read_json(self.server.root/'fault.json',256)['mode']==mode:
                    time.sleep(0.01)
            if mode=='lose-manifest' and '/commits/' in key:
                replace_json(self.server.root/'fault.json',{'mode':'normal'})
                self.server.record(self.command,self.path,0);self.connection.shutdown(socket.SHUT_RDWR);self.close_connection=True;return
            self.response(200,b'',{'ETag':'"'+digest+'"','x-amz-version-id':digest});return
        if meta is None:self.error(404,'NoSuchKey');return
        if mode=='deny-data' and key.endswith('.parquet'):self.error(403,'AccessDenied');return
        if query.get('versionId') is not None and query['versionId']!=[meta['version']]:self.error(404,'NoSuchVersion');return
        if self.headers.get('If-Match') not in (None,'"'+meta['etag']+'"',meta['etag']):self.error(412,'PreconditionFailed');return
        headers={'ETag':'"'+meta['etag']+'"','x-amz-version-id':meta['version'],'Last-Modified':'Fri, 10 Jul 2026 18:00:00 GMT','Content-Type':'application/octet-stream'}
        body=(self.server.root/'objects'/meta['file']).read_bytes()
        if mode=='corrupt-data' and key.endswith('.parquet') and body:body=bytes([body[0]^1])+body[1:]
        self.response(200,body,headers)
    def guarded(self):
        try:self.handle_request()
        except (ValueError,KeyError,OSError,json.JSONDecodeError):
            self.close_connection=True
    do_GET=guarded
    do_HEAD=guarded
    do_PUT=guarded

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True);parser.add_argument('--fixture-id',required=True);parser.add_argument('--bucket',default='signal-fixture');parser.add_argument('--port',type=int,default=0)
    args=parser.parse_args();fixture_id=str(uuid.UUID(args.fixture_id))
    if fixture_id!=args.fixture_id or not (0<=args.port<=65535) or args.bucket!='signal-fixture':raise ValueError('fixture arguments')
    server=Fixture(args.root,fixture_id,args.bucket,args.port)
    replace_json(args.root/'endpoint.json',{'url':f'http://127.0.0.1:{server.server_port}','pid':os.getpid(),'fixture_id':fixture_id})
    try:server.serve_forever(poll_interval=0.05)
    finally:server.server_close()
if __name__=='__main__':main()

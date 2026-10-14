#!/usr/bin/env python3
"""Offline verification of a pinned-key, signed artifact inventory. No installation."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile

DOMAIN = b'PLATFORM::SIGNAL/artifact-inventory/v1\0'
MAX_DOCUMENT = 262144
MAX_FILES = 128
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024

def bounded(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('document type or byte limit')
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError('document byte limit')
    return data

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate inventory field')
        result[key] = value
    return result

def artifact(root, name):
    if not isinstance(name, str) or len(name) > 256 or not re.fullmatch(r'[A-Za-z0-9_./-]+', name):
        raise ValueError('artifact path')
    parts = PurePosixPath(name).parts
    if not parts or name != '/'.join(parts) or any(p in ('.', '..') for p in parts) or name.startswith('/'):
        raise ValueError('artifact path')
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('artifact symlink')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= MAX_FILE_BYTES:
            raise ValueError('artifact type or bytes')
        h = hashlib.sha256()
        count = 0
        while chunk := source.read(131072):
            count += len(chunk)
            if count > MAX_FILE_BYTES:
                raise ValueError('artifact byte limit')
            h.update(chunk)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or count != before.st_size:
            raise ValueError('artifact changed during verification')
    return {'path': name, 'bytes': count, 'sha256': h.hexdigest()}

def verify(root, public_key):
    root = Path(root).resolve()
    key = bounded(Path(public_key), 4096)
    raw = bounded(root / 'inventory.json', MAX_DOCUMENT)
    signature = bounded(root / 'inventory.sig', 64)
    if len(signature) != 64:
        raise ValueError('signature length')
    # The externally pinned key is the sole trust root. Never take a key from
    # the signed inventory or an adjacent package key as implicit authority.
    with tempfile.TemporaryDirectory(prefix='signal-trust-') as directory:
        tmp = Path(directory)
        (tmp / 'key.pem').write_bytes(key)
        (tmp / 'payload').write_bytes(DOMAIN + raw)
        (tmp / 'sig').write_bytes(signature)
        parsed = subprocess.run(['openssl', 'pkey', '-pubin', '-in', str(tmp / 'key.pem'),
            '-outform', 'DER', '-out', str(tmp / 'key.der')], timeout=5,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if parsed.returncode:
            raise ValueError('pinned public key')
        der = bounded(tmp / 'key.der', 4096)
        if len(der) != 44 or der[:12] != bytes.fromhex('302a300506032b6570032100'):
            raise ValueError('Ed25519 public key required')
        result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin',
            '-inkey', str(tmp / 'key.pem'), '-in', str(tmp / 'payload'), '-sigfile', str(tmp / 'sig')],
            timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if result.returncode:
            raise ValueError('pinned-key signature verification failed')
    manifest = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(manifest, dict) or set(manifest) != {'schema_version', 'revision', 'purpose', 'artifacts'}:
        raise ValueError('inventory schema')
    if type(manifest['schema_version']) is not int or manifest['schema_version'] != 1 or manifest['purpose'] != 'local-test':
        raise ValueError('inventory version or purpose')
    if not isinstance(manifest['revision'], str) or not re.fullmatch('[0-9a-f]{40}', manifest['revision']):
        raise ValueError('source revision')
    entries = manifest['artifacts']
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_FILES:
        raise ValueError('inventory file count')
    names = set()
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'path', 'bytes', 'sha256'} or type(entry['bytes']) is not int or not 0 <= entry['bytes'] <= MAX_FILE_BYTES or not isinstance(entry['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', entry['sha256']):
            raise ValueError('inventory artifact schema')
        name = entry['path']
        if not isinstance(name, str) or name in names:
            raise ValueError('duplicate artifact path')
        total += entry['bytes']
        if total > MAX_TOTAL_BYTES:
            raise ValueError('inventory total bytes')
        names.add(name)
        if artifact(root, name) != entry:
            raise ValueError('artifact identity mismatch')
    return {'status': 'verified_local_test', 'revision': manifest['revision'], 'artifacts': len(entries),
            'bytes': total, 'pinned_key_sha256': hashlib.sha256(key).hexdigest(),
            'inventory_sha256': hashlib.sha256(raw).hexdigest(), 'production_release': False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.bundle, args.public_key)))
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(1, 'Artifact verification rejected: ' + type(error).__name__ + '\n')

if __name__ == '__main__':
    main()

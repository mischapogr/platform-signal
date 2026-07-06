#!/usr/bin/env python3
"""Prepare or verify unsigned, unpublished local development artifacts."""
import argparse
import contextlib
import gzip
import hashlib
import io
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SOURCE_CAP = 16 * 1024 * 1024
EVIDENCE_CAP = 64 * 1024 * 1024
IMAGE_CAP = 512 * 1024 * 1024
JSON_CAP = 2 * 1024 * 1024
FILE_COUNT = 1024
VERSION = '0.1.0-dev.0'
ARTIFACTS = ('source.tar.gz', 'signal-0.1.0.tgz', 'evidence.tar.gz', 'image.tar')
TOP_FILES = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'LICENSE', '.dockerignore', '.gitignore',
             'AGENTS.md', 'CLAUDE.md', 'README.md', 'BENCHMARKS.md', 'CHANGELOG.md', 'CODE_OF_CONDUCT.md',
             'CONTRIBUTING.md', 'SECURITY.md', 'UPGRADING.md', 'docker-compose.yml'}
CRATES = ('event', 'protocol', 'ingest', 'buffer', 'storage', 'query', 'rules', 'findings', 'collector-sdk', 'coverage')
MEMBERS = tuple('crates/signal-' + name for name in CRATES) + tuple('apps/' + name for name in ('signal-server', 'signal-agent', 'signalctl'))
LEGACY_MEMBERS = tuple(name for name in MEMBERS if name != 'crates/signal-coverage')
FIXTURE_FILES = {'schemas/source-coverage.schema.json', 'schemas/source-coverage-profile.schema.json',
                 'tests/fixtures/security-requirements/catalog.json', 'tests/fixtures/source-coverage/contract.json',
                 'tests/fixtures/source-coverage/history.json', 'tests/fixtures/source-coverage/backend-vectors.json'}
SAMPLE_FILES = {'examples/logs/' + name for name in (
    'README.md', 'manifest.json', 'canonical.ndjson', 'ingest-batch.json',
    'aws-cloudtrail.json', 'aws-cloudwatch.json', 'aws-rds.json', 'aws-alb.json',
    'aws-nlb.json', 'aws-eks.json', 'aws-ecs.json', 'cloudflare.json', 'office365.json',
    'cato-vpn.json', 'fortigate.json')}
CHART_FILES = {'Chart.yaml', 'README.md', 'values.yaml', 'values.schema.json',
               'templates/_helpers.tpl', 'templates/configmap.yaml', 'templates/deployment.yaml',
               'templates/pdb.yaml', 'templates/pvc.yaml', 'templates/service.yaml', 'templates/servicemonitor.yaml'}
EVIDENCE_ROOTS = ('target/phase10-header-buffer-20261006', 'target/phase10-longer-soak-20261006/review',
                  'target/phase10-longer-buffered-20261006', 'target/phase10-query-reads-20261006',
                  'target/release-gates-20261007/accepted')
AWS_REPORT = 'target/release-tools-20261006/installation.json'
HASH = re.compile(r'[0-9a-f]{64}')


def safe_name(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '\\' in name or any(part in ('', '.', '..') for part in name.split('/')):
        raise RuntimeError('unsafe archive/path name: ' + name)
    return path


def source_allowed(name):
    safe_name(name)
    if name in TOP_FILES or name == '.github/workflows/ci.yml':
        return True
    if name in FIXTURE_FILES or name in SAMPLE_FILES:
        return True
    parts = name.split('/')
    if any(part.startswith('.') or part in ('private', 'node_modules', 'data', 'target') for part in parts):
        return False
    if name.startswith('docs/'):
        return name.endswith('.md')
    if name.startswith('scripts/'):
        return name.endswith('.py') or name == 'scripts/ai/context7'
    if name.startswith('benchmarks/'):
        return name in {'benchmarks/README.md', 'benchmarks/harness.rs', 'benchmarks/pipeline.py', 'benchmarks/soak.py'}
    if name.startswith('tests/integration/'):
        return name.endswith(('.py', '.rs', '.md'))
    if name == 'rules/examples/login-failure.yaml':
        return True
    if name in {'deploy/compose/server.yaml', 'deploy/docker/Dockerfile', 'deploy/docker/README.md', 'deploy/docker/healthcheck.rs'}:
        return True
    if name.startswith('deploy/helm/signal/'):
        return name.removeprefix('deploy/helm/signal/') in CHART_FILES
    for member in MEMBERS:
        if name.startswith(member + '/'):
            tail = name[len(member) + 1:]
            return tail in ('Cargo.toml', 'README.md') or tail.startswith(('src/', 'tests/', 'examples/')) and tail.endswith('.rs')
    return False


def evidence_allowed(name):
    safe_name(name)
    if name == AWS_REPORT:
        return True
    if not any(name.startswith(prefix + '/') for prefix in EVIDENCE_ROOTS):
        return False
    return name.endswith(('.json', '.log', '.py', '.yaml', '.patch', '.rs')) and not any(
        part.startswith('.') for part in name.split('/'))


def regular(path, root):
    relative = path.relative_to(root)
    for index in range(1, len(relative.parts) + 1):
        if (root.joinpath(*relative.parts[:index])).is_symlink():
            raise RuntimeError('symlink input refused: ' + str(relative))
    if not path.is_file():
        raise RuntimeError('regular file required: ' + str(relative))


def digest_stream(stream, cap):
    digest, count = hashlib.sha256(), 0
    while True:
        block = stream.read(min(1048576, cap + 1 - count))
        if not block:
            break
        count += len(block)
        if count > cap:
            raise RuntimeError('stream/file bound exceeded')
        digest.update(block)
    return digest.hexdigest(), count


def file_info(path, cap):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > cap:
        raise RuntimeError('missing, linked or oversized file: ' + str(path))
    with path.open('rb') as stream:
        digest, size = digest_stream(stream, cap)
    return {'sha256': digest, 'bytes': size}


def read_json(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('missing or linked JSON file: ' + str(path))
    with path.open('rb') as stream:
        data = stream.read(JSON_CAP + 1)
    if len(data) > JSON_CAP:
        raise RuntimeError('JSON file bound exceeded')
    return json.loads(data)


def write_json(path, value):
    encoded = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    if len(encoded) > JSON_CAP:
        raise RuntimeError('manifest/report cap')
    # Replace only our own manifest; output directory was exclusively created.
    temp = path.with_suffix('.tmp')
    with temp.open('wb') as stream:
        stream.write(encoded)
    temp.replace(path)


def collect(root, prefixes, allowed):
    selected = []
    def walk(directory):
        for entry in sorted(directory.iterdir()):
            name = entry.relative_to(root).as_posix()
            if entry.is_symlink():
                if allowed(name):
                    raise RuntimeError('allowlisted symlink refused: ' + name)
                continue
            if entry.is_dir():
                if not entry.name.startswith('.') and entry.name not in ('target', 'node_modules', 'private', 'data'):
                    walk(entry)
            elif allowed(name):
                regular(entry, root)
                selected.append(name)
                if len(selected) > FILE_COUNT:
                    raise RuntimeError('file-count bound')
    for prefix in prefixes:
        path = root / prefix
        if path.is_symlink():
            raise RuntimeError('root symlink refused')
        if path.is_dir():
            walk(path)
        elif path.exists() and allowed(prefix):
            regular(path, root)
            selected.append(prefix)
    return sorted(set(selected))


def entry_cap(kind, name):
    if kind in ('source', 'chart'):
        return 1048576
    if name.endswith('.json'):
        return JSON_CAP
    return SOURCE_CAP


class HashingReader:
    def __init__(self, stream):
        self.stream, self.digest = stream, hashlib.sha256()
    def read(self, count):
        data = self.stream.read(count)
        self.digest.update(data)
        return data


def archive(output, root, names, prefix, kind, cap):
    files, total = {}, 0
    with output.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as bundle:
            for name in names:
                regular(root / name, root)
                before = file_info(root / name, entry_cap(kind, name))
                total += before['bytes']
                if total > cap or len(files) >= FILE_COUNT:
                    raise RuntimeError('archive aggregate bound')
                member = prefix + name
                safe_name(member)
                info = tarfile.TarInfo(member)
                mode = 0o755 if (root / name).stat().st_mode & 0o111 else 0o644
                info.size, info.mode, info.mtime = before['bytes'], mode, 0
                with (root / name).open('rb') as stream:
                    reader = HashingReader(stream)
                    bundle.addfile(info, reader)
                after = file_info(root / name, entry_cap(kind, name))
                if after != before or reader.digest.hexdigest() != before['sha256']:
                    raise RuntimeError('input changed during copy: ' + name)
                files[member] = {**before, 'mode': mode}
    summary = file_info(output, cap)
    summary.update(kind=kind, files=files, file_count=len(files), content_bytes=total)
    return summary


def tar_envelope(path, compressed, cap, metadata=False):
    """Bound raw tar framing before tarfile can allocate extended-header data."""
    # Two terminator blocks plus up to 19 record-alignment blocks emitted by
    # tarfile.close(): a final member ending one block before a record boundary
    # needs 21 zero blocks, rather than just one 20-block record.
    zero_tail_cap = tarfile.RECORDSIZE + tarfile.BLOCKSIZE
    with path.open('rb') as raw:
        stream = gzip.GzipFile(fileobj=raw) if compressed else raw
        try:
            total = entries = zeros = 0
            while True:
                header = stream.read(512)
                if not header:
                    if zeros < 2:
                        raise RuntimeError('tar terminator missing')
                    return
                total += len(header)
                if len(header) != 512 or total > cap + FILE_COUNT * 1024 + zero_tail_cap:
                    raise RuntimeError('tar framing/decompressed envelope bound')
                if header == b'\0' * 512:
                    zeros += 1
                    if zeros * 512 > zero_tail_cap:
                        raise RuntimeError('tar trailing padding bound')
                    continue
                if zeros:
                    raise RuntimeError('nonzero data after tar terminator')
                info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
                entries += 1
                if entries > FILE_COUNT:
                    raise RuntimeError('raw tar header count bound')
                if info.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
                    if not metadata or info.type not in (tarfile.XHDTYPE, tarfile.XGLTYPE) or info.size > 16384:
                        raise RuntimeError('extended/sparse tar metadata refused')
                if info.size < 0 or info.size > cap or total + info.size > cap + FILE_COUNT * 1024:
                    raise RuntimeError('raw tar payload bound')
                remaining = (info.size + 511) // 512 * 512
                while remaining:
                    block = stream.read(min(1048576, remaining))
                    if not block:
                        raise RuntimeError('truncated tar payload')
                    remaining -= len(block)
                    total += len(block)
        finally:
            if stream is not raw:
                stream.close()


def archive_contents(path, kind, cap, expected=None):
    file_info(path, cap)
    tar_envelope(path, True, cap)
    files, total = {}, 0
    with tarfile.open(path, 'r|gz') as bundle:
        for member in bundle:
            safe_name(member.name)
            if not member.isfile() or member.name in files or len(files) >= FILE_COUNT:
                raise RuntimeError('archive type/duplicate/count violation')
            if kind == 'source':
                allowed = member.name.startswith('platform-signal/') and source_allowed(member.name.removeprefix('platform-signal/'))
            elif kind == 'chart':
                allowed = member.name.startswith('signal/') and member.name.removeprefix('signal/') in CHART_FILES
            else:
                allowed = member.name.startswith('evidence/') and evidence_allowed(member.name.removeprefix('evidence/'))
            total += member.size
            if not allowed or member.size > entry_cap(kind, member.name) or total > cap:
                raise RuntimeError('archive allowlist/size violation')
            stream = bundle.extractfile(member)
            digest, count = digest_stream(stream, member.size)
            stream.close()
            if count != member.size:
                raise RuntimeError('truncated member')
            if member.mode not in (0o644, 0o755) or member.uid != 0 or member.gid != 0 or member.mtime != 0 or member.uname or member.gname:
                raise RuntimeError('archive deterministic ownership/mode/time mismatch')
            files[member.name] = {'sha256': digest, 'bytes': count, 'mode': member.mode}
    result = {'files': files, 'file_count': len(files), 'content_bytes': total}
    if expected is not None and any(result[key] != expected[key] for key in result):
        raise RuntimeError('archive inventory differs from manifest')
    return result


def archived_json(path, name):
    with tarfile.open(path, 'r:gz') as bundle:
        stream = bundle.extractfile(name)
        if stream is None:
            raise RuntimeError('required archived report missing')
        try:
            data = stream.read(JSON_CAP + 1)
        finally:
            stream.close()
        if len(data) > JSON_CAP:
            raise RuntimeError('archived report cap')
        return json.loads(data)


def docker_archive(path, image_id):
    """No layer extraction: verify config and ordered uncompressed layer hashes."""
    file_info(path, IMAGE_CAP)
    tar_envelope(path, False, IMAGE_CAP, metadata=True)
    members, total = {}, 0
    with tarfile.open(path, 'r:') as bundle:
        for member in bundle:
            name = member.name.rstrip('/') if member.isdir() else member.name
            safe_name(name)
            if name in members or not (member.isfile() or member.isdir()) or len(members) >= FILE_COUNT:
                raise RuntimeError('Docker outer archive path/type/duplicate/count violation')
            total += member.size
            if member.size > IMAGE_CAP or total > IMAGE_CAP:
                raise RuntimeError('Docker archive aggregate bound')
            members[name] = member
        def data(name):
            if name not in members or not members[name].isfile() or members[name].size > JSON_CAP:
                raise RuntimeError('Docker JSON member missing/oversized')
            stream = bundle.extractfile(members[name])
            try:
                return stream.read(JSON_CAP + 1)
            finally:
                stream.close()
        manifest = json.loads(data('manifest.json'))
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise RuntimeError('Docker archive must contain exactly one image')
        record = manifest[0]
        safe_name(record['Config'])
        config_data = data(record['Config'])
        if 'sha256:' + hashlib.sha256(config_data).hexdigest() != image_id:
            raise RuntimeError('Docker image config digest mismatch')
        config = json.loads(config_data)
        if config.get('os') != 'linux' or config.get('architecture') != 'amd64':
            raise RuntimeError('Docker archive architecture mismatch')
        layers, diff_ids = record['Layers'], config['rootfs']['diff_ids']
        if not layers or len(layers) > 128 or len(layers) != len(diff_ids) or len(set(layers)) != len(layers):
            raise RuntimeError('Docker ordered layer count mismatch')
        results, expanded = [], 0
        for name, expected in zip(layers, diff_ids):
            safe_name(name)
            if name not in members or not members[name].isfile() or not re.fullmatch('sha256:[0-9a-f]{64}', expected):
                raise RuntimeError('Docker layer reference invalid')
            stream = bundle.extractfile(members[name])
            try:
                first = stream.read(2)
            finally:
                stream.close()
            stream = bundle.extractfile(members[name])
            reader = gzip.GzipFile(fileobj=stream) if first == b'\x1f\x8b' else stream
            try:
                digest, size = digest_stream(reader, IMAGE_CAP - expanded)
            finally:
                reader.close()
                stream.close()
            expanded += size
            if 'sha256:' + digest != expected:
                raise RuntimeError('Docker layer diff_id mismatch')
            # Modern save uses content-addressed blobs; verify stored bytes too.
            if name.startswith('blobs/sha256/'):
                stream = bundle.extractfile(members[name])
                try:
                    stored, _ = digest_stream(stream, IMAGE_CAP)
                finally:
                    stream.close()
                if name.rsplit('/', 1)[1] != stored:
                    raise RuntimeError('Docker blob digest mismatch')
            results.append({'path': name, 'diff_id': expected, 'uncompressed_bytes': size})
        return {'config_sha256': image_id.removeprefix('sha256:'), 'architecture': 'amd64', 'os': 'linux',
                'layers': results, 'outer_members': len(members), 'content_bytes': total,
                'uncompressed_layer_bytes': expanded, 'repo_tags': record.get('RepoTags')}


@contextlib.contextmanager
def defer_signals():
    prior, pending = {}, []
    def defer(signum, frame):
        pending[:] = [signum]
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            prior[signum] = signal.getsignal(signum)
            signal.signal(signum, defer)
        yield
    finally:
        for signum, handler in prior.items():
            signal.signal(signum, handler)
    if pending:
        raise KeyboardInterrupt('interrupt during owned process registration')


def run(command, record, timeout=30, bounded_file=None, cap=IMAGE_CAP):
    """Bound output and kill the owned process group before reaping the leader."""
    process = selector = None
    captured = bytearray()
    entry = {'command': [str(value) for value in command], 'status': 'failed', 'timeout_seconds': timeout}
    record.append(entry)
    deadline = time.monotonic() + timeout
    try:
        with defer_signals():
            process = subprocess.Popen(entry['command'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            if time.monotonic() >= deadline:
                raise RuntimeError('command deadline')
            if bounded_file is not None and bounded_file.exists() and bounded_file.stat().st_size > cap:
                raise RuntimeError('generated artifact cap')
            for key, _ in selector.select(0.05):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                else:
                    if len(captured) + len(block) > 65536:
                        raise RuntimeError('command output cap')
                    captured.extend(block)
            exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if exited is not None and not selector.get_map():
                break
        entry['exit_code'] = exited.si_status
        if exited.si_code != os.CLD_EXITED or exited.si_status:
            raise RuntimeError('command failed: ' + entry['command'][0])
        entry['status'] = 'passed'
        return captured.decode(errors='replace').strip()
    finally:
        try:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                finally:
                    process.stdout.close()
        finally:
            if selector is not None:
                selector.close()
            entry['captured_output'] = captured.decode(errors='replace')


def validate_workspace(source_files, read_text):
    cfg = tomllib.loads(read_text('Cargo.toml'))
    members = cfg['workspace']['members']
    if cfg['workspace']['package']['version'] != VERSION or frozenset(members) not in (frozenset(MEMBERS), frozenset(LEGACY_MEMBERS)) or len(members) != len(set(members)):
        raise RuntimeError('workspace version/member mismatch')
    required = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'LICENSE', 'benchmarks/harness.rs',
                'benchmarks/pipeline.py', 'benchmarks/soak.py', 'rules/examples/login-failure.yaml',
                'deploy/docker/healthcheck.rs', 'tests/integration/foundation.rs'} | {name + '/Cargo.toml' for name in members}
    if not required <= set(source_files):
        raise RuntimeError('source archive lacks required workspace inputs')
    if any(name.startswith(member + '/') for member in set(MEMBERS) - set(members) for name in source_files):
        raise RuntimeError('undeclared workspace member in source')
    for member in members:
        config = tomllib.loads(read_text(member + '/Cargo.toml'))
        if config['package'].get('publish') is not False:
            raise RuntimeError('package publish policy differs from unpublished contract')
    for name in source_files:
        if name.endswith('.rs'):
            for reference in re.findall(r'include_(?:str|bytes)!\s*\(\s*"([^"\n]+)"', read_text(name)):
                included = posixpath.normpath(str(PurePosixPath(name).parent / reference))
                safe_name(included)
                if included not in source_files:
                    raise RuntimeError('missing compile-time source input: ' + included)


def bind_review(review, root):
    if review.get('schema_version') != 1 or review.get('status') != 'accepted' or review.get('unresolved_findings') != []:
        raise RuntimeError('accepted review with no unresolved findings required')
    for field in ('source_sha256', 'artifact_sha256'):
        if not isinstance(review.get(field), dict) or not review[field]:
            raise RuntimeError('review lacks bounded source/artifact bindings')
        for name, digest in review[field].items():
            safe_name(name)
            if not HASH.fullmatch(digest):
                raise RuntimeError('invalid review digest')
            regular(root / name, root)
            if file_info(root / name, EVIDENCE_CAP)['sha256'] != digest:
                raise RuntimeError('review binding changed: ' + name)


def normalize_image_report(value):
    """Normalize one bound report or Docker's one-image inspection array."""
    if isinstance(value, list):
        if len(value) != 1:
            raise RuntimeError('image inspection must describe exactly one image')
        value = value[0]
    if isinstance(value, dict):
        value = value.get('image', value)
    if not isinstance(value, dict):
        raise RuntimeError('unsupported image report shape')
    if {'id', 'os', 'architecture'} <= value.keys():
        return {key: value[key] for key in ('id', 'os', 'architecture')}
    if {'Id', 'Os', 'Architecture'} <= value.keys():
        return {'id': value['Id'], 'os': value['Os'], 'architecture': value['Architecture']}
    raise RuntimeError('image report lacks identity or architecture')


def exclusions(evidence, root):
    """Describe hash references outside the selected evidence/source, without copying them."""
    result = {}
    for name in evidence:
        if not name.endswith('.json'):
            continue
        value = read_json(root / name)
        def visit(node):
            if isinstance(node, dict):
                for key, item in node.items():
                    if isinstance(item, str) and HASH.fullmatch(item) and isinstance(key, str) and '/' in key:
                        try:
                            safe_name(key)
                        except RuntimeError:
                            continue
                        if key not in evidence and not source_allowed(key):
                            result[key] = {'sha256': item, 'reason': 'outside positive evidence/source selection; retained reference only'}
                    else:
                        visit(item)
            elif isinstance(node, list):
                for item in node:
                    visit(item)
        visit(value)
    return result


def checksums(output):
    names = ('candidate.json',) + ARTIFACTS
    (output / 'SHA256SUMS').write_text(''.join(file_info(output / name, IMAGE_CAP)['sha256'] + '  ' + name + '\n' for name in names))


def snapshot_deltas(snapshot, source_info):
    omissions, changes = [], []
    for name, old in snapshot.items():
        safe_name(name)
        if name not in source_info:
            if source_allowed(name):
                raise RuntimeError('reviewed source omitted: ' + name)
            omissions.append({'path': name, **old, 'reason': 'outside positive OSS source allowlist'})
        elif source_info[name]['sha256'] != old['sha256']:
            if not name.endswith('.md'):
                raise RuntimeError('unreviewed non-document source change: ' + name)
            changes.append({'path': name, 'accepted_sha256': old['sha256'],
                            'prepared_sha256': source_info[name]['sha256'], 'reason': 'local preparation documentation update'})
    for name in set(source_info) - set(snapshot):
        if name not in ('scripts/prepare-local-candidate.py', 'scripts/test-local-candidate.py') and not name.endswith('.md'):
            raise RuntimeError('unreviewed new source input: ' + name)
        changes.append({'path': name, 'prepared_sha256': source_info[name]['sha256'], 'reason': 'local preparation addition'})
    return sorted(omissions, key=lambda item: item['path']), sorted(changes, key=lambda item: item['path'])


def own_output(output, root):
    root = root.absolute()
    output = output.absolute()
    try:
        relative = output.relative_to(root / 'target')
    except ValueError as error:
        raise RuntimeError('output must be a new directory under repository target') from error
    if not relative.parts or any(part in ('.', '..') for part in relative.parts):
        raise RuntimeError('invalid output boundary')
    for ancestor in (output, *output.parents):
        if ancestor.is_symlink():
            raise RuntimeError('output ancestor symlink refused')
        if ancestor == root:
            break
    if output.exists():
        raise FileExistsError('existing candidate preserved')
    output.mkdir(parents=True, exist_ok=False)


def prepare(image_id, review_path, output, root=ROOT):
    # No write, Docker operation or validation happens before collision-safe ownership.
    own_output(output, root)
    manifest = {'schema_version': 1, 'status': 'failed', 'scope': 'unpublished-local-preparation',
                'version': VERSION, 'git_commit': None, 'local_unpublished': True,
                'full_release': False, 'registry_ready': False, 'commands': [], 'artifacts': {},
                'image': {'id': image_id, 'source_snapshot_exact': False},
                'limits': {'source_bytes': SOURCE_CAP, 'evidence_bytes': EVIDENCE_CAP,
                           'image_bytes': IMAGE_CAP, 'archive_files': FILE_COUNT},
                'evidence_selection_scope': 'Positive suffix selection in specifically retained Phase10/current accepted release-gate directories plus AWS installation JSON; not full historical/tooling closure.',
                'runtime_contents': ['signal-server', 'signal-agent', 'signal-healthcheck'], 'signalctl_source_only': True,
                'source_image_relation': 'Current source preparation snapshot; runtime image predates new preparation scripts/documentation.'}
    write_json(output / 'candidate.json', manifest)
    try:
        if not re.fullmatch('sha256:[0-9a-f]{64}', image_id):
            raise RuntimeError('immutable image ID required')
        if platform.system() != 'Linux' or platform.machine() != 'x86_64':
            raise RuntimeError('native Linux AMD64 host required')
        regular(review_path, root)
        review = read_json(review_path)
        bind_review(review, root)
        image_reports = [name for name in review['artifact_sha256'] if name.endswith('/image.json')]
        matching = []
        for name in image_reports:
            value = read_json(root / name)
            candidate = normalize_image_report(value)
            if candidate.get('id') == image_id and candidate.get('architecture') == 'amd64' and candidate.get('os') == 'linux':
                matching.append(name)
        if not matching:
            raise RuntimeError('image is not bound by accepted review')
        manifest['review'] = {'path': review_path.relative_to(root).as_posix(), **file_info(review_path, JSON_CAP), 'status': 'accepted'}
        manifest['deferred_gates'] = review.get('remaining_external_gates', [])
        manifest['accepted_source_sha256'] = review['source_sha256']
        daemon = json.loads(run(['docker', 'info', '--format', '{"os":{{json .OSType}},"architecture":{{json .Architecture}}}'], manifest['commands']))
        image = json.loads(run(['docker', 'image', 'inspect', '--format', '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"size":{{json .Size}}}', image_id], manifest['commands']))
        if daemon.get('os') != 'linux' or daemon.get('architecture') not in ('amd64', 'x86_64') or image.get('id') != image_id or image.get('os') != 'linux' or image.get('architecture') != 'amd64' or not 0 < image.get('size', 0) <= IMAGE_CAP:
            raise RuntimeError('native daemon/image identity or size mismatch')
        manifest['daemon'], manifest['image'] = daemon, {**image, 'source_snapshot_exact': False}
        origins = [name for name in review['artifact_sha256'] if name.endswith('/extraction/origin.json')]
        if len(origins) != 1:
            raise RuntimeError('one accepted binary origin required')
        origin = read_json(root / origins[0])
        if origin['image']['id'] != image_id or not HASH.fullmatch(origin['binary_sha256']):
            raise RuntimeError('accepted binary/image origin mismatch')
        manifest['image']['binary_sha256'] = origin['binary_sha256']
        source = collect(root, tuple(TOP_FILES) + ('.github/workflows/ci.yml', 'apps', 'crates', 'benchmarks', 'docs', 'scripts', 'tests/integration', 'tests/fixtures', 'schemas', 'examples/logs', 'rules', 'deploy'), source_allowed)
        validate_workspace(source, lambda name: (root / name).read_text())
        snapshot_names = [name for name in review['artifact_sha256'] if name.endswith('/source-snapshot.json')]
        if len(snapshot_names) != 1:
            raise RuntimeError('one accepted source snapshot required')
        snapshot = read_json(root / snapshot_names[0])['files']
        source_info = {name: file_info(root / name, SOURCE_CAP) for name in source}
        omissions, changes = snapshot_deltas(snapshot, source_info)
        manifest['accepted_snapshot_omissions'], manifest['preparation_changes'] = omissions, changes
        manifest['artifacts']['source.tar.gz'] = archive(output / 'source.tar.gz', root, source, 'platform-signal/', 'source', SOURCE_CAP)
        chart_root = root / 'deploy/helm'
        manifest['artifacts']['signal-0.1.0.tgz'] = archive(output / 'signal-0.1.0.tgz', chart_root, ['signal/' + name for name in sorted(CHART_FILES)], '', 'chart', SOURCE_CAP)
        evidence = collect(root, EVIDENCE_ROOTS + (AWS_REPORT,), evidence_allowed)
        if manifest['review']['path'] not in evidence or not set(review['artifact_sha256']) <= set(evidence):
            raise RuntimeError('accepted review/artifact evidence missing from selection')
        manifest['excluded_evidence_references'] = exclusions(evidence, root)
        manifest['artifacts']['evidence.tar.gz'] = archive(output / 'evidence.tar.gz', root, evidence, 'evidence/', 'evidence', EVIDENCE_CAP)
        # Recheck all accepted bindings after source/evidence copying.
        bind_review(review, root)
        image_path = output / 'image.tar'
        run(['docker', 'image', 'save', '--output', image_path, image_id], manifest['commands'], timeout=180, bounded_file=image_path)
        image_summary = file_info(image_path, IMAGE_CAP)
        image_summary.update(kind='docker-image', verification=docker_archive(image_path, image_id))
        manifest['artifacts']['image.tar'] = image_summary
        manifest['status'] = 'prepared'
        write_json(output / 'candidate.json', manifest)
        checksums(output)
        verify(output)
        return manifest
    except BaseException as error:
        manifest.update(status='failed', error=str(error)[:2048], partial_artifacts_removed=[])
        for name in ARTIFACTS + ('SHA256SUMS',):
            path = output / name
            if path.exists():
                path.unlink()
                manifest['partial_artifacts_removed'].append(name)
        write_json(output / 'candidate.json', manifest)
        raise


def verify(output):
    if output.is_symlink() or not output.is_dir():
        raise RuntimeError('candidate must be regular owned directory')
    expected_names = set(ARTIFACTS) | {'candidate.json', 'SHA256SUMS'}
    if {path.name for path in output.iterdir()} != expected_names:
        raise RuntimeError('candidate has missing or unexpected entries')
    manifest = read_json(output / 'candidate.json')
    if manifest.get('schema_version') != 1 or manifest.get('status') != 'prepared' or manifest.get('scope') != 'unpublished-local-preparation' or manifest.get('version') != VERSION or manifest.get('git_commit') is not None or manifest.get('local_unpublished') is not True or manifest.get('full_release') is not False or manifest.get('registry_ready') is not False:
        raise RuntimeError('manifest scope/status/version mismatch')
    if set(manifest['artifacts']) != set(ARTIFACTS):
        raise RuntimeError('artifact inventory mismatch')
    sums_path = output / 'SHA256SUMS'
    file_info(sums_path, 1024)
    sums = {}
    for line in sums_path.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([a-zA-Z0-9.-]+)', line)
        if not match or match[2] in sums:
            raise RuntimeError('checksum syntax/duplicate')
        sums[match[2]] = match[1]
    if set(sums) != expected_names - {'SHA256SUMS'}:
        raise RuntimeError('checksum inventory missing/extra')
    inventories = {}
    for name in expected_names - {'SHA256SUMS'}:
        cap = IMAGE_CAP if name == 'image.tar' else EVIDENCE_CAP if name == 'evidence.tar.gz' else SOURCE_CAP if name.endswith(('.gz', '.tgz')) else JSON_CAP
        info = file_info(output / name, cap)
        if info['sha256'] != sums[name]:
            raise RuntimeError('checksum mismatch: ' + name)
        if name != 'candidate.json' and any(info[key] != manifest['artifacts'][name][key] for key in info):
            raise RuntimeError('manifest file checksum/size mismatch')
    for name, kind, cap in [('source.tar.gz', 'source', SOURCE_CAP), ('signal-0.1.0.tgz', 'chart', SOURCE_CAP), ('evidence.tar.gz', 'evidence', EVIDENCE_CAP)]:
        inventories[kind] = archive_contents(output / name, kind, cap, manifest['artifacts'][name])
    image_id = manifest['image']['id']
    if not re.fullmatch('sha256:[0-9a-f]{64}', image_id) or manifest['image'].get('architecture') != 'amd64' or manifest['image'].get('os') != 'linux' or manifest['image'].get('source_snapshot_exact') is not False:
        raise RuntimeError('manifest image identity mismatch')
    if docker_archive(output / 'image.tar', image_id) != manifest['artifacts']['image.tar']['verification']:
        raise RuntimeError('Docker verification differs from manifest')
    review_name = 'evidence/' + manifest['review']['path']
    if inventories['evidence']['files'][review_name]['sha256'] != manifest['review']['sha256']:
        raise RuntimeError('review archive digest mismatch')
    review = archived_json(output / 'evidence.tar.gz', review_name)
    if review.get('status') != 'accepted' or review.get('unresolved_findings') != [] or manifest['accepted_source_sha256'] != review['source_sha256']:
        raise RuntimeError('archived accepted review mismatch')
    if manifest.get('deferred_gates') != review.get('remaining_external_gates', []):
        raise RuntimeError('deferred gates differ from archived accepted review')
    for name, digest in review['source_sha256'].items():
        if inventories['source']['files']['platform-signal/' + name]['sha256'] != digest:
            raise RuntimeError('accepted source differs from archived source')
    for name, digest in review['artifact_sha256'].items():
        if inventories['evidence']['files']['evidence/' + name]['sha256'] != digest:
            raise RuntimeError('accepted evidence differs from archived evidence')
    source_info = {name.removeprefix('platform-signal/'): info for name, info in inventories['source']['files'].items()}
    source_path = output / 'source.tar.gz'
    def source_text(name):
        with tarfile.open(source_path, 'r:gz') as bundle:
            stream = bundle.extractfile('platform-signal/' + name)
            try:
                data = stream.read(1048577)
            finally:
                stream.close()
            if len(data) > 1048576:
                raise RuntimeError('source text bound')
            return data.decode()
    validate_workspace(set(source_info), source_text)
    snapshots = [name for name in review['artifact_sha256'] if name.endswith('/source-snapshot.json')]
    origins = [name for name in review['artifact_sha256'] if name.endswith('/extraction/origin.json')]
    if len(snapshots) != 1 or len(origins) != 1:
        raise RuntimeError('accepted snapshot/binary origin missing')
    snapshot = archived_json(output / 'evidence.tar.gz', 'evidence/' + snapshots[0])['files']
    omissions, changes = snapshot_deltas(snapshot, source_info)
    if manifest['accepted_snapshot_omissions'] != omissions or manifest['preparation_changes'] != changes:
        raise RuntimeError('preparation changes/omissions differ from accepted snapshot')
    origin = archived_json(output / 'evidence.tar.gz', 'evidence/' + origins[0])
    if origin['image']['id'] != image_id or origin['image'].get('os') != 'linux' or origin['image'].get('architecture') != 'amd64' or manifest['image']['binary_sha256'] != origin['binary_sha256']:
        raise RuntimeError('manifest image/binary differs from archived accepted origin')
    bound_image = False
    for name in review['artifact_sha256']:
        if name.endswith('/image.json'):
            image_report = archived_json(output / 'evidence.tar.gz', 'evidence/' + name)
            image = normalize_image_report(image_report)
            if image.get('id') == image_id and image.get('os') == 'linux' and image.get('architecture') == 'amd64':
                bound_image = True
    if not bound_image:
        raise RuntimeError('manifest image not bound by archived accepted review')
    chart_files = inventories['chart']['files']
    if set(chart_files) != {'signal/' + name for name in CHART_FILES}:
        raise RuntimeError('chart required files missing')
    for name, info in chart_files.items():
        if inventories['source']['files']['platform-signal/deploy/helm/' + name] != info:
            raise RuntimeError('chart differs from source preparation')
    return {'schema_version': 1, 'status': 'verified', 'scope': 'offline-unsigned-local-integrity',
            'full_release': False, 'image_id': image_id, 'artifacts': len(ARTIFACTS)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('prepare')
    build.add_argument('--image', required=True)
    build.add_argument('--review', type=Path, required=True)
    build.add_argument('--output', type=Path, required=True)
    check = sub.add_parser('verify')
    check.add_argument('--candidate', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'verify':
        print(json.dumps(verify(args.candidate), sort_keys=True))
    else:
        result = prepare(args.image, args.review.resolve(strict=True), args.output)
        print(json.dumps({'status': result['status'], 'output': str(args.output)}, sort_keys=True))
    return 0


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt('interrupted by signal ' + str(signum))
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())

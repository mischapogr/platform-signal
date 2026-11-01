#!/usr/bin/env python3
"""Read-only consistency check of saved public-preview records, never a live gate."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import uuid

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 128 * 1024
INPUTS = ('docker-compose.yml', 'deploy/compose/server.yaml',
          'rules/examples/login-failure.yaml', 'examples/local-preview/compose.yaml',
          'examples/local-preview/events.json')
SUITE_PINS = {
    'examples/local-preview/events.json': '5770cf768f2a773cd48845d523b6e51e6c6681c47e67331c7445f02a79dfd5ad',
    'rules/examples/login-failure.yaml': '63fd6f292877a8ba1441816f512adbc7dbcc6721cf770ef6af9db66e5f7d98a5',
}


class PreviewError(ValueError):
    """Only static, non-sensitive validation labels belong in these errors."""


def require(value, label):
    if not value:
        raise PreviewError(label)


def unique(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate JSON field')
        value[key] = item
    return value


def decode(raw):
    require(len(raw) <= LIMIT, 'bounded JSON required')
    def invalid(_):
        raise PreviewError('nonfinite JSON refused')
    def number(value):
        parsed = float(value)
        require(math.isfinite(parsed), 'nonfinite JSON refused')
        return parsed
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid, parse_float=number)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def read_regular(path=None, *, name=None, directory=None):
    # O_NONBLOCK ensures a mistakenly supplied FIFO cannot block opening. Size
    # and pre/post metadata are snapshots, not continuous filesystem attestation.
    descriptor = os.open(path if path is not None else name,
                         os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= LIMIT, 'bounded single-link regular file required')
        chunks, count = [], 0
        while True:
            block = os.read(descriptor, min(65536, LIMIT + 1 - count))
            if not block:
                break
            count += len(block)
            require(count <= LIMIT, 'file grew beyond byte bound')
            chunks.append(block)
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, field) == getattr(after, field) for field in fields),
                'file changed during read')
        return b''.join(chunks)
    finally:
        os.close(descriptor)


def schema(value):
    require(type(value) is dict and type(value.get('schema_version')) is int
            and value['schema_version'] == 1, 'schema version one required')


def verify(evidence, source_commit, image_reference, image_id):
    require(re.fullmatch('[0-9a-f]{40}', source_commit) is not None, 'full source commit pin required')
    require(re.fullmatch(r'[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}', image_reference) is not None,
            'digest-pinned image reference required')
    require(re.fullmatch('sha256:[0-9a-f]{64}', image_id) is not None, 'image ID pin required')
    directory = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        record_hashes = {}
        def read(name):
            raw = read_regular(name=name, directory=directory)
            record_hashes[name] = hashlib.sha256(raw).hexdigest()
            return raw
        def text(name):
            return read(name).decode('utf-8').strip()
        project = text('project.txt')
        require(re.fullmatch('signal-preview-[0-9a-f]{12}', project) is not None, 'owned preview project record required')
        require(text('source-commit.txt') == source_commit, 'recorded source commit differs from pin')
        require(text('image-reference.txt') == image_reference, 'recorded image reference differs from pin')
        inspection = text('image.txt').split(' ', 1)
        require(len(inspection) == 2 and inspection[0] == image_id, 'recorded image ID differs from pin')
        digests = decode(inspection[1].encode())
        require(type(digests) is list and all(type(item) is str for item in digests)
                and image_reference in digests, 'image reference absent from recorded RepoDigests')
        declared = {}
        for line in text('inputs.sha256').splitlines():
            match = re.fullmatch('([0-9a-f]{64})  ([a-zA-Z0-9_/.-]+)', line)
            require(match is not None, 'invalid input hash record')
            digest, name = match.groups()
            require(name in INPUTS and name not in declared, 'unknown or duplicate input path')
            declared[name] = digest
        require(set(declared) == set(INPUTS), 'complete closed input inventory required')
        current = {name: read_regular(ROOT / name) for name in INPUTS}
        require(all(hashlib.sha256(raw).hexdigest() == declared[name] for name, raw in current.items()),
                'input hashes differ from current files')
        require(all(declared[name] == digest for name, digest in SUITE_PINS.items()), 'unsupported fixture or rule suite')
        expected = decode(current['examples/local-preview/events.json'])['events']
        require(type(expected) is list and len(expected) == 4, 'exact four-event fixture suite required')
        expected_by_id = {event['id']: event for event in expected}
        require(len(expected_by_id) == 4, 'unique fixture IDs required')
        for name, status in [('admission-http.txt', '202'), ('events-http.txt', '200'), ('findings-http.txt', '200')]:
            require(text(name) == status, 'required HTTP status not recorded')
        admission = decode(read('admission.json'))
        schema(admission)
        require(type(admission.get('accepted')) is int and admission['accepted'] == 4
                and type(admission.get('rejected')) is int and admission['rejected'] == 0
                and admission.get('event_ids') == [event['id'] for event in expected]
                and admission.get('error') is None, 'complete ordered admission required')
        response = decode(read('events.json'))
        schema(response)
        events = response.get('events')
        require(type(events) is list and len(events) == 4
                and all(type(event) is dict and type(event.get('id')) is str for event in events),
                'exact queried event population required')
        require({event['id'] for event in events} == set(expected_by_id), 'missing, extra or duplicate event ID')
        require(all(canonical(event) == canonical(expected_by_id[event['id']]) for event in events),
                'queried event payload differs from fixture')
        response = decode(read('findings.json'))
        schema(response)
        findings = response.get('findings')
        require(type(findings) is list and len(findings) == 2, 'exact finding population required')
        expected_matches = {event['id'] for event in expected if 'login failed' in event['message']}
        matched, finding_ids = set(), set()
        for finding in findings:
            schema(finding)
            require(set(finding) == {'schema_version', 'id', 'rule_id', 'created_at', 'severity', 'title', 'event_ids', 'attributes'}
                    and type(finding['attributes']) is dict and not finding['attributes'], 'fixed fixture finding envelope required')
            require(finding.get('rule_id') == 'auth.login-failure'
                    and finding.get('severity') == 'medium'
                    and finding.get('title') == 'Failed login detected', 'wrong finding rule metadata')
            references = finding.get('event_ids')
            require(type(references) is list and len(references) == 1 and type(references[0]) is str
                    and references[0] in expected_matches and references[0] not in matched,
                    'missing, duplicate or unexpected finding event reference')
            require(type(finding.get('id')) is str, 'finding UUID required')
            identity = uuid.UUID(finding['id'])
            require(identity.int != 0 and str(identity) == finding['id'] and identity not in finding_ids,
                    'unique canonical finding UUID required')
            require(finding.get('created_at') == expected_by_id[references[0]]['observed_at'],
                    'finding creation time differs from fixture')
            matched.add(references[0])
            finding_ids.add(identity)
        require(matched == expected_matches, 'complete finding coverage required')
        return {'status': 'consistent_saved_preview_records', 'scope': 'offline_record_consistency_only',
                'schema_version': 1, 'source_commit': source_commit, 'image_id': image_id,
                'image_reference_sha256': hashlib.sha256(image_reference.encode()).hexdigest(),
                'input_sha256': declared, 'record_sha256': record_hashes, 'events': 4, 'findings': 2, 'input_files': len(INPUTS),
                'source_commit_pin_matched': True, 'image_pins_matched': True,
                'image_source_build_binding_verified': False, 'capture_authenticity_verified': False,
                'finding_id_derivation_verified': False,
                'live_requests_performed': False, 'browser_verified': False,
                'durability_or_capacity_qualified': False, 'profile_load_completed': False,
                'alpha_or_release_qualified': False}
    finally:
        os.close(directory)


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise PreviewError("invalid command line")


def main():
    parser = Arguments(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--image-reference', required=True)
    parser.add_argument('--image-id', required=True)
    try:
        args = parser.parse_args()
        result = verify(args.evidence, args.source_commit, args.image_reference, args.image_id)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        # Never echo input values, arbitrary paths, server bodies or tokens.
        print(json.dumps({'status': 'invalid_or_incomplete_preview_records',
                          'scope': 'offline_record_consistency_only'}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

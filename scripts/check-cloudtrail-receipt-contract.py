#!/usr/bin/env python3
"""Offline schema/encoding/transition oracle. Not a custody backend or authority verifier."""
import argparse
import datetime as dt
import hashlib
import json
import math
import re
import struct
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/cloudtrail-receipt/contract.json'
MIB = 1024 * 1024
MAX_U64 = 2**64 - 1
REASONS = {'missing_required_native', 'malformed_required_native', 'unsupported_native_version',
           'unsupported_event_category', 'recipient_route_not_authorized', 'missing_actor',
           'unsupported_operation', 'missing_or_unsupported_mfa', 'unsupported_actor_mfa',
           'unknown_operation_outcome', 'prepared_event_bytes_exceeded'}
OBJECT_REASONS = {'invalid_compression', 'invalid_object_json', 'object_limits_exceeded',
                  'unsupported_object', 'empty_records'}


class ContractError(ValueError):
    pass


def require(ok, reason='contract violation'):
    if not ok:
        raise ContractError(reason)


def keys(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()), 'schema fields')


def uint(value, maximum=MAX_U64, minimum=0):
    require(type(value) is int and minimum <= value <= maximum, 'unsigned integer')
    return value


def text(value, maximum, empty=False):
    require(isinstance(value, str), 'string type')
    try:
        data = value.encode('utf-8')
    except UnicodeError as exc:
        raise ContractError('unicode scalar') from exc
    require((empty or len(data) > 0) and len(data) <= maximum, 'string bytes')
    return value


def uid(value):
    require(isinstance(value, str), 'UUID type')
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise ContractError('UUID') from exc
    require(parsed.int != 0 and str(parsed) == value, 'UUID canonical')
    return parsed.bytes


def digest(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'hash')
    return bytes.fromhex(value)


def clock(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}Z', value), 'UTC form')
    try:
        stamp = dt.datetime.strptime(value[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise ContractError('UTC calendar') from exc
    # Integer nanoseconds, no float rounding and no microsecond truncation.
    return (stamp - dt.datetime(1, 1, 1, tzinfo=dt.timezone.utc)).days * 86400 * 10**9 + (stamp.hour * 3600 + stamp.minute * 60 + stamp.second) * 10**9 + int(value[20:29])


def quoted(value):
    text(value, MIB, empty=True)
    return '"' + ''.join('\\"' if c == '"' else '\\\\' if c == '\\' else f'\\u{ord(c):04x}' if ord(c) < 32 else c for c in value) + '"'


def canonical(value):
    def encode(v):
        if v is None:
            return 'null'
        if type(v) is bool:
            return 'true' if v else 'false'
        if type(v) is int:
            return str(uint(v))
        if isinstance(v, str):
            return quoted(v)
        if isinstance(v, list):
            return '[' + ','.join(encode(x) for x in v) + ']'
        require(isinstance(v, dict) and all(isinstance(k, str) for k in v), 'JSON type')
        return '{' + ','.join(quoted(k) + ':' + encode(v[k]) for k in sorted(v)) + '}'
    return encode(value).encode('utf-8')


def parse_json(data, cap, exact=False, event=False):
    require(len(data) <= cap, 'JSON bytes')
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, 'duplicate key')
            result[k] = v
        return result
    def invalid(_):
        raise ContractError('float/nonfinite JSON')
    def event_float(value):
        parsed = float(value)
        require(math.isfinite(parsed), 'nonfinite event JSON')
        return parsed
    try:
        result = json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_int=(lambda v: int(v)) if event else (lambda v: uint(int(v))), parse_float=event_float if event else invalid, parse_constant=invalid)
        encoded = None if event else canonical(result)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ContractError('invalid JSON') from exc
    require(not exact or encoded == data, 'noncanonical JSON')
    return result


def account(value):
    require(isinstance(value, str) and re.fullmatch('[0-9]{12}', value), 'account')


def reasons(value, allowed, minimum):
    require(isinstance(value, list) and minimum <= len(value) <= 4, 'reason count')
    require(all(isinstance(x, str) and x in allowed for x in value) and len(set(value)) == len(value), 'reason enum/duplicate')


def validate_metadata(m):
    keys(m, 'schema_version receipt_id binding original prepared_at normalizer_sha256 retention object_disposition object_reasons records')
    require(type(m['schema_version']) is int and m['schema_version'] == 1, 'schema version')
    uid(m['receipt_id']); digest(m['normalizer_sha256'])
    b = m['binding']
    keys(b, 'tenant_id collector_id source_id config_revision authority_revision queue_arn trail_arn queue_owner bucket_owner bucket key_prefix stream profile_id profile_revision recipient_accounts regions custody_mode ack_requires_m2')
    for k in ['tenant_id', 'collector_id', 'source_id', 'config_revision', 'authority_revision', 'stream', 'profile_id', 'profile_revision']:
        text(b[k], 128)
    for k in ['queue_arn', 'trail_arn']:
        text(b[k], 512)
    for k in ['queue_owner', 'bucket_owner']:
        account(b[k])
    text(b['bucket'], 63); text(b['key_prefix'], 1024, empty=True)
    require(b['profile_id'] == 'cloudtrail-management' and b['profile_revision'] == 'v1', 'profile')
    require(b['custody_mode'] in ['process_local', 'independent_durable', 'protected_replay'], 'custody mode')
    require(type(b['ack_requires_m2']) is bool, 'ACK boolean')
    for name, maximum in [('recipient_accounts', 128), ('regions', 64)]:
        items = b[name]
        require(isinstance(items, list) and 1 <= len(items) <= maximum, 'scope count')
        for item in items:
            if name == 'recipient_accounts':
                account(item)
            else:
                text(item, 64); require(re.fullmatch('[a-z0-9-]+', item), 'region')
        require(items == sorted(set(items)), 'scope order/duplicate')
    o = m['original']
    keys(o, 'bucket key version_id etag compression length sha256 decoded_length captured_at discovery_sha256 delivery_id reference_count')
    text(o['bucket'], 63); text(o['key'], 1024); text(o['version_id'], 1024)
    require(o['version_id'] != 'null', 'null version')
    if o['etag'] is not None:
        text(o['etag'], 1024)
    text(o['delivery_id'], 128); digest(o['sha256']); digest(o['discovery_sha256'])
    require(o['compression'] == 'gzip' and type(o['reference_count']) is int and o['reference_count'] == 1, 'original kind/reference count')
    require(o['bucket'] == b['bucket'] and o['key'].startswith(b['key_prefix']), 'source namespace')
    uint(o['length'], 8*MIB, 1); uint(o['decoded_length'], 32*MIB)
    prepared = clock(m['prepared_at']); require(clock(o['captured_at']) <= prepared, 'capture time')
    r = m['retention']; keys(r, 'retain_until source_replay_until recovery_budget_seconds')
    budget = uint(r['recovery_budget_seconds'], 2**32-1, 1) * 10**9
    end = prepared + budget
    require(end <= clock('9999-12-31T23:59:59.999999999Z'), 'retention overflow')
    require(clock(r['retain_until']) >= end and clock(r['source_replay_until']) >= end, 'recovery horizon')
    records = m['records']; require(isinstance(records, list) and len(records) <= 1024, 'record count')
    if m['object_disposition'] == 'quarantine_object':
        reasons(m['object_reasons'], OBJECT_REASONS, 1); require(not records, 'object quarantine records')
    else:
        require(m['object_disposition'] == 'prepared' and m['object_reasons'] == [] and records and o['decoded_length'] > 0, 'object disposition')
    previous_end = 0; emitted = []
    for ordinal, record in enumerate(records):
        keys(record, 'ordinal start length sha256 native_event_id disposition reasons prepared_index prepared_id prepared_sha256')
        require(uint(record['ordinal'], 1023) == ordinal, 'ordinal')
        start = uint(record['start'], 32*MIB); length = uint(record['length'], 256*1024, 1)
        require(start >= previous_end and start+length <= o['decoded_length'], 'record span')
        previous_end = start + length; digest(record['sha256'])
        if record['native_event_id'] is not None:
            uid(record['native_event_id'])
        disposition = record['disposition']
        require(disposition in ['emit', 'emit_indeterminate', 'quarantine_record'], 'record disposition')
        reasons(record['reasons'], REASONS, 0 if disposition == 'emit' else 1)
        require(disposition != 'emit' or record['reasons'] == [], 'emit reasons')
        if disposition == 'quarantine_record':
            require(all(record[k] is None for k in ['prepared_index', 'prepared_id', 'prepared_sha256']), 'quarantine mapping')
        else:
            require(uint(record['prepared_index'], 1023) == len(emitted), 'prepared index')
            uid(record['prepared_id']); digest(record['prepared_sha256'])
            require(all(record['prepared_id'] != x['prepared_id'] for x in emitted), 'duplicate prepared identity')
            emitted.append(record)
    require(len(canonical(m)) <= MIB, 'metadata bytes')
    return emitted


def verify_binding(metadata, trusted_binding):
    validate_metadata(metadata)
    require(metadata['binding'] == trusted_binding, 'full trusted binding mismatch')


def event_matches(data, metadata, record):
    event = parse_json(data, 65536, event=True)
    require(isinstance(event, dict) and type(event.get('schema_version')) is int and event.get('schema_version') == 1, 'event version')
    require(event.get('id') == record['prepared_id'] and event.get('observed_at') == metadata['prepared_at'], 'event pins')
    attrs = event.get('attributes', {})
    require(isinstance(attrs, dict) and attrs.get('normalizer') == {'id': 'cloudtrail-management', 'revision': 'v1'}, 'event profile')
    require(attrs.get('evidence_ref') == f"receipt://{metadata['receipt_id']}/record/{record['ordinal']}", 'event evidence ref')


def encode_receipt(metadata, original, events):
    emitted = validate_metadata(metadata)
    require(isinstance(original, bytes) and len(original) == metadata['original']['length'] and hashlib.sha256(original).hexdigest() == metadata['original']['sha256'], 'original witness')
    require(isinstance(events, list) and len(events) == len(emitted), 'prepared count')
    total = 0
    blocks = []
    for record, data in zip(emitted, events):
        require(isinstance(data, bytes) and 1 <= len(data) <= 65536, 'event length')
        require(hashlib.sha256(data).hexdigest() == record['prepared_sha256'], 'event hash')
        event_matches(data, metadata, record)
        total += len(data); require(total <= 16*MIB, 'prepared total')
        blocks.append(struct.pack('>I', len(data)) + uid(record['prepared_id']) + digest(record['prepared_sha256']) + data)
    encoded = canonical(metadata)
    require(36 + 52*len(events) + 32 <= 65536, 'framing allowance')
    require(36 + len(encoded) + len(original) + total + 52*len(events) + 32 <= 32*MIB, 'receipt bytes')
    body = b'SIGSRC01' + struct.pack('>IQQQ', len(encoded), len(original), len(events), total) + encoded + original + b''.join(blocks)
    return body + hashlib.sha256(body).digest()


def decode_receipt(data):
    require(isinstance(data, bytes) and 68 <= len(data) <= 32*MIB and data[:8] == b'SIGSRC01', 'receipt frame')
    ml, ol, count, total = struct.unpack('>IQQQ', data[8:36])
    require(ml <= MIB and 1 <= ol <= 8*MIB and count <= 1024 and total <= 16*MIB, 'receipt header limits')
    require(len(data) == 36 + ml + ol + count*52 + total + 32, 'receipt section sum')
    require(hashlib.sha256(data[:-32]).digest() == data[-32:], 'receipt checksum')
    metadata = parse_json(data[36:36+ml], MIB, exact=True)
    original = data[36+ml:36+ml+ol]
    offset = 36 + ml + ol; events = []
    for _ in range(count):
        require(offset + 52 <= len(data)-32, 'event frame truncation')
        length = struct.unpack('>I', data[offset:offset+4])[0]
        require(1 <= length <= 65536 and offset+52+length <= len(data)-32, 'event frame length')
        payload = data[offset+52:offset+52+length]
        require(hashlib.sha256(payload).digest() == data[offset+20:offset+52], 'frame hash')
        event = parse_json(payload, 65536, event=True)
        require(isinstance(event, dict), 'event object')
        require(uid(event.get('id')) == data[offset+4:offset+20], 'frame UUID')
        events.append(payload); offset += 52 + length
    require(offset == len(data)-32, 'event total/trailing bytes')
    require(encode_receipt(metadata, original, events) == data, 'receipt correspondence')
    return metadata, original, events


def prefix_hash(receipt_digest, emitted, prefix):
    uint(prefix, len(emitted))
    body = b'SIGPRF01' + digest(receipt_digest) + struct.pack('>I', prefix)
    for record in emitted[:prefix]:
        body += uid(record['prepared_id']) + digest(record['prepared_sha256'])
    return hashlib.sha256(body).hexdigest()


def validate_progress(p, metadata, receipt_digest):
    emitted = validate_metadata(metadata)
    keys(p, 'schema_version receipt_id receipt_sha256 binding retention prepared_count owner_id owner_generation revision previous_sha256 verified_prefix prefix_sha256 attempt custody ack retirement')
    require(type(p['schema_version']) is int and p['schema_version'] == 1, 'progress version')
    require(p['receipt_id'] == metadata['receipt_id'] and p['receipt_sha256'] == receipt_digest, 'progress binding')
    require(p['binding'] == metadata['binding'] and p['retention'] == metadata['retention'] and type(p['prepared_count']) is int and p['prepared_count'] == len(emitted), 'progress recovery binding')
    uid(p['owner_id']); uint(p['owner_generation'], minimum=1); uint(p['revision'])
    if p['previous_sha256'] is not None:
        digest(p['previous_sha256'])
    require((p['previous_sha256'] is None) == (p['revision'] == 0), 'progress previous')
    prefix = uint(p['verified_prefix'], len(emitted))
    require(p['prefix_sha256'] == prefix_hash(receipt_digest, emitted, prefix), 'prefix witness')
    a = p['attempt']; keys(a, 'kind start count accepted response_sha256')
    start = uint(a['start'], len(emitted)); count = uint(a['count'], len(emitted)); accepted = uint(a['accepted'], count)
    if a['kind'] == 'none':
        require(start == count == accepted == 0 and a['response_sha256'] is None, 'empty attempt')
    else:
        require(a['kind'] in ['verified', 'uncertain', 'permanent'] and count > 0 and start+count <= len(emitted), 'attempt bounds/kind')
        require(start+accepted == prefix, 'attempt prefix')
        if a['kind'] == 'verified':
            digest(a['response_sha256'])
        else:
            require(accepted == 0 and a['response_sha256'] is None, 'uncertain progress')
    c = p['custody']; keys(c, 'status witness_id receipt_sha256 retain_until')
    if c['status'] == 'verified_independent':
        text(c['witness_id'], 512)
        require(c['receipt_sha256'] == receipt_digest and clock(c['retain_until']) >= clock(metadata['retention']['retain_until']), 'custody witness binding')
    else:
        require(c['status'] in ['pending', 'local_only'] and all(c[k] is None for k in ['witness_id', 'receipt_sha256', 'retain_until']), 'custody state')
    ack = p['ack']; keys(ack, 'state attempt_id delivery_id observed_at')
    require(ack['state'] in ['not_requested', 'intent', 'uncertain', 'confirmed'], 'ACK state')
    if ack['state'] == 'not_requested':
        require(all(ack[k] is None for k in ['attempt_id', 'delivery_id', 'observed_at']), 'empty ACK')
    else:
        uid(ack['attempt_id']); text(ack['delivery_id'], 128)
        require(clock(ack['observed_at']) >= clock(metadata['prepared_at']), 'ACK time')
    retired = p['retirement']; keys(retired, 'state observed_at')
    require(retired['state'] in ['active', 'intent', 'complete'], 'retirement state')
    if retired['state'] == 'active':
        require(retired['observed_at'] is None, 'active retirement time')
    else:
        require(prefix == len(emitted) and ack['state'] == 'confirmed' and clock(retired['observed_at']) >= clock(metadata['retention']['retain_until']), 'retirement pins')
    if p['revision'] == 0:
        require(prefix == 0 and a['kind'] == 'none' and c['status'] == 'local_only' and ack['state'] == 'not_requested' and retired['state'] == 'active', 'initial progress')
    require(len(canonical(p)) + 44 <= 8*MIB, 'progress bytes')


def encode_progress(p, metadata, receipt_digest):
    validate_progress(p, metadata, receipt_digest)
    data = canonical(p)
    body = b'SIGSCP01' + struct.pack('>I', len(data)) + data
    return body + hashlib.sha256(body).digest()


def decode_progress(data, metadata, receipt_digest):
    require(44 <= len(data) <= 8*MIB and data[:8] == b'SIGSCP01', 'progress frame')
    length = struct.unpack('>I', data[8:12])[0]
    require(length + 44 == len(data), 'progress length')
    require(hashlib.sha256(data[:-32]).digest() == data[-32:], 'progress checksum')
    p = parse_json(data[12:-32], 8*MIB-44, exact=True)
    require(encode_progress(p, metadata, receipt_digest) == data, 'progress correspondence')
    return p


def authority_ok(authority):
    require(all(authority.get(k) is True for k in ['fresh_grant', 'exclusive_owner', 'history_known']), 'external ownership/authority/history')


def ack_allowed(p, metadata, authority):
    validate_progress(p, metadata, p['receipt_sha256'])
    authority_ok(authority)
    if metadata['binding']['ack_requires_m2']:
        require(p['verified_prefix'] == len(validate_metadata(metadata)), 'ACK needs M2')
    if p['custody']['status'] == 'verified_independent':
        require(authority.get('custody_witness_verified') is True, 'independent custody authority')
    else:
        require(metadata['binding']['custody_mode'] == 'process_local' and p['custody']['status'] == 'local_only' and authority.get('process_local_authorized') is True, 'required custody unavailable')


def transition(old, new, metadata, receipt_digest, kind, authority):
    validate_progress(old, metadata, receipt_digest); validate_progress(new, metadata, receipt_digest)
    authority_ok(authority)
    require(new['revision'] == old['revision'] + 1 and new['previous_sha256'] == encode_progress(old, metadata, receipt_digest)[-32:].hex(), 'progress chain')
    require(new['verified_prefix'] >= old['verified_prefix'], 'prefix rollback')
    require(old['retirement']['state'] == 'active' or kind in ['retire', 'takeover'], 'retiring receipt side effect')
    changed = {k for k in old if old[k] != new[k]} - {'revision', 'previous_sha256'}
    if kind == 'takeover':
        require(changed <= {'owner_id', 'owner_generation', 'attempt'} and new['owner_id'] != old['owner_id'] and new['owner_generation'] == old['owner_generation']+1 and new['attempt']['kind'] == 'none', 'owner takeover')
        return
    require(new['owner_id'] == old['owner_id'] and new['owner_generation'] == old['owner_generation'], 'stale owner')
    if kind == 'retire':
        require(changed <= {'attempt', 'retirement'} and new['attempt']['kind'] == 'none', 'retire changes')
        require((old['retirement']['state'], new['retirement']['state']) in [('active', 'intent'), ('intent', 'complete')], 'retire transition')
        reclaim_allowed(new, metadata, new['retirement']['observed_at'], authority)
        if new['retirement']['state'] == 'complete':
            require(authority.get('reclaim_files_deleted_and_synced') is True and clock(new['retirement']['observed_at']) >= clock(old['retirement']['observed_at']), 'reclaim result')
    elif kind == 'send':
        require(changed <= {'attempt', 'verified_prefix', 'prefix_sha256'} and new['attempt']['kind'] != 'none' and new['attempt']['start'] == old['verified_prefix'], 'send transition')
        require(new['attempt']['kind'] != 'verified' or authority.get('response_verified') is True, 'unverified HTTP response')
    elif kind == 'custody':
        require(changed <= {'attempt', 'custody'} and new['attempt']['kind'] == 'none' and new['custody']['status'] == 'verified_independent' and authority.get('custody_witness_verified') is True, 'custody transition')
    elif kind == 'ack':
        require(changed <= {'attempt', 'ack'} and new['attempt']['kind'] == 'none', 'ACK changes')
        state = old['ack']['state']; target = new['ack']['state']
        require((state, target) in [('not_requested', 'intent'), ('intent', 'uncertain'), ('intent', 'confirmed'), ('uncertain', 'intent'), ('confirmed', 'intent')], 'ACK transition')
        ack_allowed(new, metadata, authority)
        if target == 'intent':
            require(authority.get('fresh_delivery') is True and new['ack']['attempt_id'] != old['ack']['attempt_id'], 'fresh delete attempt')
        else:
            require(new['ack']['attempt_id'] == old['ack']['attempt_id'] and new['ack']['delivery_id'] == old['ack']['delivery_id'], 'ACK attempt binding')
            require(target != 'confirmed' or authority.get('ack_response_verified') is True, 'unverified delete result')
        if old['ack']['observed_at'] is not None:
            require(clock(new['ack']['observed_at']) >= clock(old['ack']['observed_at']), 'ACK time rollback')
    else:
        raise ContractError('transition kind')


def reclaim_allowed(p, metadata, now, authority):
    validate_progress(p, metadata, p['receipt_sha256'])
    authority_ok(authority)
    require(p['verified_prefix'] == len(validate_metadata(metadata)) and p['ack']['state'] == 'confirmed' and clock(now) >= clock(metadata['retention']['retain_until']), 'retained work/horizon')


def check_fixture(path=FIXTURE):
    fixture = parse_json(path.read_bytes(), 2*MIB)
    require(fixture['schema_version'] == 1 and fixture['status'] == 'offline_schema_contract', 'fixture scope')
    receipts = {}
    for vector in fixture['receipt_vectors']:
        original = bytes.fromhex(vector['original_hex']); events = [x.encode('utf-8') for x in vector['events_utf8']]
        data = encode_receipt(vector['metadata'], original, events)
        require(data.hex() == vector['wire_hex'] and hashlib.sha256(data).hexdigest() == vector['file_sha256'], 'receipt golden pin')
        require(decode_receipt(data) == (vector['metadata'], original, events), 'receipt round trip')
        receipts[vector['id']] = (vector['metadata'], data[-32:].hex())
    progresses = {}
    for vector in fixture['progress_vectors']:
        m, h = receipts[vector['receipt']]
        data = encode_progress(vector['progress'], m, h)
        require(data.hex() == vector['wire_hex'] and hashlib.sha256(data).hexdigest() == vector['file_sha256'], 'progress golden pin')
        require(decode_progress(data, m, h) == vector['progress'], 'progress round trip')
        progresses[vector['id']] = vector['progress']
    for case in fixture['transitions']:
        m, h = receipts[case['receipt']]
        failed = False
        try:
            transition(progresses[case['from']], progresses[case['to']], m, h, case['kind'], case['authority'])
        except ContractError:
            failed = True
        require(failed != case['allowed'], 'transition witness')
    for case in fixture['reclaim_cases']:
        m, _ = receipts[case['receipt']]
        failed = False
        try:
            reclaim_allowed(progresses[case['progress']], m, case['now'], case['authority'])
        except ContractError:
            failed = True
        require(failed != case['allowed'], 'reclaim witness')
    return {'schema_version': 1, 'status': 'passed', 'scope': 'offline_schema_encoding_and_transition_witnesses_only', 'receipt_vectors': len(receipts), 'progress_vectors': len(progresses), 'transitions': len(fixture['transitions']), 'reclaim_cases': len(fixture['reclaim_cases']), 'fixture_sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'runtime_custody_qualified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, default=FIXTURE)
    args = parser.parse_args()
    try:
        print(json.dumps(check_fixture(args.fixture), sort_keys=True))
    except (ContractError, KeyError, TypeError, ValueError, OSError) as exc:
        parser.exit(1, f'CloudTrail receipt contract rejected: {type(exc).__name__}\n')

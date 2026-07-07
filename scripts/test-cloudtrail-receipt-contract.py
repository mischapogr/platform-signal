#!/usr/bin/env python3
"""Offline negative and relational checks; no Rust/backend/cloud assurance."""
import copy
import gzip
import hashlib
import importlib.util
import json
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('receipt_contract', Path(__file__).with_name('check-cloudtrail-receipt-contract.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
FIXTURE = json.loads(c.FIXTURE.read_text())
VECTORS = {v['id']: v for v in FIXTURE['receipt_vectors']}
PROGRESSES = {v['id']: v for v in FIXTURE['progress_vectors']}
A = {'fresh_grant': True, 'exclusive_owner': True, 'history_known': True,
     'response_verified': True, 'process_local_authorized': True,
     'custody_witness_verified': True, 'fresh_delivery': True,
     'ack_response_verified': True, 'reclaim_files_deleted_and_synced': True}
REJECTIONS = 0


def seal(body):
    return body + hashlib.sha256(body).digest()


class ReceiptContractTests(unittest.TestCase):
    def setUp(self):
        self.v = copy.deepcopy(VECTORS['prepared'])
        self.m = self.v['metadata']
        self.original = bytes.fromhex(self.v['original_hex'])
        self.events = [e.encode() for e in self.v['events_utf8']]
        self.wire = bytes.fromhex(self.v['wire_hex'])
        self.h = self.wire[-32:].hex()

    def rejected(self, fn, *args):
        global REJECTIONS
        with self.assertRaises(c.ContractError):
            fn(*args)
        REJECTIONS += 1

    def encode(self, m):
        return c.encode_receipt(m, self.original, self.events)

    def test_frozen_vectors_and_transition_inventory(self):
        result = c.check_fixture()
        self.assertEqual((result['receipt_vectors'], result['progress_vectors'], result['transitions'], result['reclaim_cases']), (3, 20, 27, 7))
        self.assertFalse(result['runtime_custody_qualified'])

    def test_wire_pins_with_separate_structural_reader(self):
        # No reference encoder call: inspect literal sections via independent offsets.
        self.assertEqual(self.wire[:8], b'SIGSRC01')
        ml = int.from_bytes(self.wire[8:12], 'big')
        ol = int.from_bytes(self.wire[12:20], 'big')
        count = int.from_bytes(self.wire[20:28], 'big')
        total = int.from_bytes(self.wire[28:36], 'big')
        self.assertEqual(json.loads(self.wire[36:36+ml]), self.m)
        self.assertEqual(self.wire[36+ml:36+ml+ol], self.original)
        self.assertEqual((count, total), (2, sum(map(len, self.events))))
        pos = 36+ml+ol
        for record, event in zip(self.m['records'], self.events):
            self.assertEqual(int.from_bytes(self.wire[pos:pos+4], 'big'), len(event))
            self.assertEqual(self.wire[pos+4:pos+20].hex(), record['prepared_id'].replace('-', ''))
            self.assertEqual(self.wire[pos+20:pos+52].hex(), hashlib.sha256(event).hexdigest())
            self.assertEqual(self.wire[pos+52:pos+52+len(event)], event)
            pos += 52+len(event)
        self.assertEqual(pos, len(self.wire)-32)
        self.assertEqual(self.wire[-32:], hashlib.sha256(self.wire[:-32]).digest())

    def test_original_record_spans_against_literal_decompressed_witness(self):
        decoded = gzip.decompress(self.original)  # Tiny trusted fixture, not a qualified bounded reader.
        self.assertEqual(len(decoded), self.m['original']['decoded_length'])
        natives = json.loads(decoded)['Records']
        for record, native in zip(self.m['records'], natives):
            raw = decoded[record['start']:record['start']+record['length']]
            self.assertEqual(hashlib.sha256(raw).hexdigest(), record['sha256'])
            self.assertEqual(json.loads(raw), native)
            self.assertEqual(native['eventID'], record['native_event_id'])
        self.assertEqual(self.m['records'][2]['disposition'], 'quarantine_record')

    def test_exact_canonical_scalar_bytes(self):
        expected = b'{"a":"\\u0000\\u0008\\u0009\\u000a\\u000c\\u000d\\\"\\\\/","z":"caf\xc3\xa9","\xc3\xa9":[true,false,null,18446744073709551615]}'
        self.assertEqual(c.canonical({'é': [True, False, None, 2**64-1], 'z': 'café', 'a': '\x00\b\t\n\f\r"\\/'}), expected)
        self.assertEqual(c.parse_json(expected, 1024, exact=True)['z'], 'café')

    def test_noncanonical_duplicate_float_unicode_json(self):
        for raw in [b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b'{ "a":1}', b'{"a":1}\n', b'{"a":1.0}', b'{"a":NaN}', b'{"a":-1}', b'{"a":18446744073709551616}', b'{"a":"\\ud800"}', b'{"a":"\\n"}', b'{"b":1,"a":2}', b'\xef\xbb\xbf{}', b'{}{}', b'\xff']:
            with self.subTest(raw=raw):
                self.rejected(c.parse_json, raw, 1024, True)
        self.rejected(c.canonical, 1.0)
        self.rejected(c.canonical, -1)
        self.rejected(c.canonical, '\udfff')

    def test_required_and_unknown_schema_keys(self):
        for path in [[], ['binding'], ['original'], ['retention'], ['records', 0]]:
            for operation in ['remove', 'unknown']:
                m = copy.deepcopy(self.m); obj = m
                for key in path:
                    obj = obj[key]
                if operation == 'remove':
                    del obj[next(iter(obj))]
                else:
                    obj['unknown'] = 'unreviewed'
                self.rejected(self.encode, m)

    def test_full_trusted_binding_each_field_is_material(self):
        c.verify_binding(self.m, self.m['binding'])
        for key in self.m['binding']:
            changed = copy.deepcopy(self.m['binding'])
            old = changed[key]
            changed[key] = ['different'] if isinstance(old, list) else not old if type(old) is bool else str(old)+'different'
            self.rejected(c.verify_binding, self.m, changed)

    def test_scope_and_original_reference_types(self):
        mutations = [('schema_version', True), ('receipt_id', '00000000-0000-0000-0000-000000000000')]
        for key, val in mutations:
            m = copy.deepcopy(self.m); m[key] = val; self.rejected(self.encode, m)
        for key, val in [('recipient_accounts', []), ('recipient_accounts', ['111122223333']*2), ('recipient_accounts', ['9'*12, '1'*12]), ('recipient_accounts', ['１'*12]), ('regions', []), ('regions', ['EU-CENTRAL-1']), ('regions', ['a'*65]), ('regions', ['a']*65), ('profile_revision', 'v2'), ('custody_mode', 'unqualified'), ('ack_requires_m2', 1), ('tenant_id', 'é'*65), ('key_prefix', 'wrong/'), ('bucket_owner', '1'*11)]:
            m = copy.deepcopy(self.m); m['binding'][key] = val; self.rejected(self.encode, m)
        for key, val in [('version_id', 'null'), ('version_id', ''), ('reference_count', 16), ('reference_count', True), ('compression', 'plain'), ('bucket', 'different'), ('length', 8*c.MIB+1), ('decoded_length', 32*c.MIB+1), ('length', True), ('sha256', 'A'*64)]:
            m = copy.deepcopy(self.m); m['original'][key] = val; self.rejected(self.encode, m)

    def test_retention_and_nanosecond_calendar_bounds(self):
        invalid = ['0000-01-01T00:00:00.000000000Z', '2026-02-30T12:00:01.000000000Z', '2026-10-07T12:00:60.000000000Z', '2026-10-07T12:00:01Z', '2026-10-07T12:00:01.000000000+00:00', '2026-10-07T12:00:01.00000000Z', '2026-10-07T12:00:01.٠٠٠٠٠٠٠٠٠Z']
        for value in invalid:
            self.rejected(c.clock, value)
        self.assertEqual(c.clock('2026-10-07T12:00:01.000000001Z') - c.clock('2026-10-07T12:00:01.000000000Z'), 1)
        for key, value in [('retain_until', self.m['prepared_at']), ('source_replay_until', self.m['prepared_at']), ('recovery_budget_seconds', 0), ('recovery_budget_seconds', True), ('recovery_budget_seconds', 2**32)]:
            m = copy.deepcopy(self.m); m['retention'][key] = value; self.rejected(self.encode, m)
        m = copy.deepcopy(self.m); m['original']['captured_at'] = m['retention']['retain_until']; self.rejected(self.encode, m)
        m = copy.deepcopy(self.m); m['prepared_at'] = '9999-12-31T23:59:59.999999999Z'; self.rejected(self.encode, m)

    def test_record_mapping_and_disposition_invariants(self):
        for index, key, value in [(0, 'ordinal', 1), (0, 'ordinal', True), (0, 'length', 0), (0, 'length', 262145), (0, 'start', 32*c.MIB), (1, 'start', 0), (1, 'prepared_index', 0), (1, 'prepared_id', self.m['records'][0]['prepared_id']), (0, 'reasons', ['unknown']), (0, 'reasons', ['missing_actor']), (2, 'reasons', []), (2, 'reasons', ['missing_actor']*2), (2, 'prepared_index', 0), (2, 'disposition', 'unknown'), (0, 'native_event_id', 'bad')]:
            m = copy.deepcopy(self.m); m['records'][index][key] = value; self.rejected(self.encode, m)
        m = copy.deepcopy(self.m); m['records'] *= 342; self.rejected(self.encode, m)
        m = copy.deepcopy(self.m); m['object_disposition'] = 'quarantine_object'; m['object_reasons'] = ['invalid_compression']; self.rejected(self.encode, m)

    def test_payload_bytes_pins_are_not_reconstructed(self):
        for original, events in [(self.original+b'x', self.events), (bytes([self.original[0]^1])+self.original[1:], self.events), (self.original, list(reversed(self.events))), (self.original, self.events[:-1]), (self.original, [self.events[0]+b' ', self.events[1]])]:
            self.rejected(c.encode_receipt, self.m, original, events)
        # A semantically equal JSON event is still different pinned bytes.
        changed = json.dumps(json.loads(self.events[0]), sort_keys=True).encode()
        self.rejected(c.encode_receipt, self.m, self.original, [changed, self.events[1]])

    def test_metadata_number_rules_do_not_narrow_event_attributes(self):
        event = json.loads(self.events[0]); event['attributes']['fixture_numbers'] = [-1, 1.25, 2**64]
        data = json.dumps(event, separators=(',', ':')).encode()
        m = copy.deepcopy(self.m); m['records'][0]['prepared_sha256'] = hashlib.sha256(data).hexdigest()
        wire = c.encode_receipt(m, self.original, [data, self.events[1]])
        self.assertEqual(c.decode_receipt(wire)[2][0], data)
        for number in ['NaN', 'Infinity', '9e999']:
            self.rejected(c.parse_json, ('{"fixture":'+number+'}').encode(), 65536, False, True)

    def test_event_context_correspondence_even_after_hash_update(self):
        for key, value in [('id', self.m['records'][1]['prepared_id']), ('observed_at', '2026-10-07T12:00:02.000000000Z'), ('schema_version', True)]:
            e = json.loads(self.events[0]); e[key] = value; data = json.dumps(e).encode()
            m = copy.deepcopy(self.m); m['records'][0]['prepared_sha256'] = hashlib.sha256(data).hexdigest()
            self.rejected(c.encode_receipt, m, self.original, [data, self.events[1]])
        for path, value in [('evidence_ref', 'receipt://different/record/0'), ('normalizer', {'id': 'cloudtrail-management', 'revision': 'v2'})]:
            e = json.loads(self.events[0]); e['attributes'][path] = value; data = json.dumps(e).encode()
            m = copy.deepcopy(self.m); m['records'][0]['prepared_sha256'] = hashlib.sha256(data).hexdigest()
            self.rejected(c.encode_receipt, m, self.original, [data, self.events[1]])

    def test_receipt_corruption_truncation_trailing_and_header_limits(self):
        for data in [self.wire[:n] for n in [0, 7, 35, 36, len(self.wire)-1]] + [self.wire+b'\0', self.wire[:-32]+b'\0'*32]:
            self.rejected(c.decode_receipt, data)
        for offset, length, value in [(8, 4, c.MIB+1), (12, 8, 8*c.MIB+1), (20, 8, 1025), (28, 8, 16*c.MIB+1)]:
            body = bytearray(self.wire[:-32]); body[offset:offset+length] = value.to_bytes(length, 'big')
            self.rejected(c.decode_receipt, seal(bytes(body)))
        body = bytearray(self.wire[:-32]); body[:8] = b'SIGSRC02'; self.rejected(c.decode_receipt, seal(bytes(body)))
        ml, ol = struct.unpack('>IQ', self.wire[8:20]); pos = 36+ml+ol
        for offset in [pos+4, pos+20, pos+52]:
            body = bytearray(self.wire[:-32]); body[offset] ^= 1; self.rejected(c.decode_receipt, seal(bytes(body)))
        body = bytearray(self.wire[:-32]); body[pos:pos+4] = (65537).to_bytes(4, 'big'); self.rejected(c.decode_receipt, seal(bytes(body)))

    def test_nonobject_event_and_size_boundaries(self):
        # Fully reseal an altered frame so rejection reaches the payload shape guard.
        m = copy.deepcopy(self.m); events = list(self.events); events[0] = b'[]'
        m['records'][0]['prepared_sha256'] = hashlib.sha256(events[0]).hexdigest()
        meta = c.canonical(m)
        body = b'SIGSRC01' + struct.pack('>IQQQ', len(meta), len(self.original), len(events), sum(map(len, events))) + meta + self.original
        for record, event in zip(m['records'], events):
            body += len(event).to_bytes(4, 'big') + bytes.fromhex(record['prepared_id'].replace('-', '')) + hashlib.sha256(event).digest() + event
        self.rejected(c.decode_receipt, seal(body))
        for length in [0, 65537]:
            payload = b'x' * length; changed = copy.deepcopy(self.m); changed['records'][0]['prepared_sha256'] = hashlib.sha256(payload).hexdigest()
            self.rejected(c.encode_receipt, changed, self.original, [payload, self.events[1]])
        q = copy.deepcopy(VECTORS['object-quarantine']['metadata'])
        original = b'x' * (8*c.MIB); q['original']['length'] = len(original); q['original']['sha256'] = hashlib.sha256(original).hexdigest()
        wire = c.encode_receipt(q, original, [])
        self.assertEqual(c.decode_receipt(wire)[1], original)
        q['original']['length'] += 1
        self.rejected(c.encode_receipt, q, original+b'x', [])

    def test_progress_binding_prefix_and_initial_state(self):
        p = copy.deepcopy(PROGRESSES['initial']['progress'])
        for key, value in [('receipt_id', '30000000-0000-4000-8000-000000000099'), ('receipt_sha256', 'f'*64), ('owner_generation', 0), ('owner_generation', True), ('verified_prefix', 3), ('verified_prefix', True), ('prefix_sha256', 'f'*64), ('previous_sha256', 'f'*64), ('prepared_count', 3), ('prepared_count', True)]:
            altered = copy.deepcopy(p); altered[key] = value; self.rejected(c.encode_progress, altered, self.m, self.h)
        p['binding']['authority_revision'] = 'different'; self.rejected(c.encode_progress, p, self.m, self.h)
        p = copy.deepcopy(PROGRESSES['initial']['progress']); p['retention']['retain_until'] = '2026-10-09T12:00:01.000000000Z'; self.rejected(c.encode_progress, p, self.m, self.h)
        p = copy.deepcopy(PROGRESSES['initial']['progress']); p['verified_prefix'] = 1; p['prefix_sha256'] = c.prefix_hash(self.h, self.m['records'][:2], 1); self.rejected(c.encode_progress, p, self.m, self.h)

    def test_attempt_uncertainty_and_prefix_order(self):
        for key, value in [('accepted', 1), ('response_sha256', 'f'*64), ('count', 0), ('start', 0), ('kind', 'invented')]:
            p = copy.deepcopy(PROGRESSES['send-uncertain']['progress']); p['attempt'][key] = value; self.rejected(c.encode_progress, p, self.m, self.h)
        emitted = self.m['records'][:2]
        self.assertNotEqual(c.prefix_hash(self.h, emitted, 2), c.prefix_hash(self.h, list(reversed(emitted)), 2))
        self.assertNotEqual(c.prefix_hash(self.h, emitted, 1), c.prefix_hash(self.h, emitted, 2))

    def test_progress_wire_corruption_and_noncanonical_payload(self):
        wire = bytes.fromhex(PROGRESSES['partial']['wire_hex'])
        for data in [wire[:-1], wire+b'x', wire[:-32]+b'\0'*32, seal(b'SIGSCP02'+wire[8:-32])]:
            self.rejected(c.decode_progress, data, self.m, self.h)
        payload = b' '+wire[12:-32]
        self.rejected(c.decode_progress, seal(b'SIGSCP01'+len(payload).to_bytes(4,'big')+payload), self.m, self.h)

    def test_transition_chain_and_owner_fields(self):
        old = PROGRESSES['initial']['progress']; new = PROGRESSES['partial']['progress']
        for key, value in [('revision', 2), ('previous_sha256', 'f'*64), ('owner_generation', 2), ('owner_id', PROGRESSES['takeover']['progress']['owner_id'])]:
            p = copy.deepcopy(new); p[key] = value; self.rejected(c.transition, old, p, self.m, self.h, 'send', A)
        p = copy.deepcopy(PROGRESSES['takeover']['progress']); p['owner_generation'] = 3
        self.rejected(c.transition, PROGRESSES['partial']['progress'], p, self.m, self.h, 'takeover', A)

    def test_ack_cannot_skip_intent_reuse_attempt_or_change_custody(self):
        old = PROGRESSES['full']['progress']; p = copy.deepcopy(PROGRESSES['intent']['progress'])
        p['ack']['state'] = 'confirmed'; self.rejected(c.transition, old, p, self.m, self.h, 'ack', A)
        p = copy.deepcopy(PROGRESSES['redelivery-intent']['progress']); p['ack']['attempt_id'] = PROGRESSES['delete-uncertain']['progress']['ack']['attempt_id']
        self.rejected(c.transition, PROGRESSES['delete-uncertain']['progress'], p, self.m, self.h, 'ack', A)
        p = copy.deepcopy(PROGRESSES['confirmed']['progress']); p['ack']['delivery_id'] = 'different'
        self.rejected(c.transition, PROGRESSES['redelivery-intent']['progress'], p, self.m, self.h, 'ack', A)
        p = copy.deepcopy(PROGRESSES['intent']['progress']); p['custody']['status'] = 'pending'
        self.rejected(c.transition, old, p, self.m, self.h, 'ack', A)

    def test_stronger_custody_requires_full_witness_and_external_verification(self):
        v = VECTORS['strong']; m = v['metadata']; h = bytes.fromhex(v['wire_hex'])[-32:].hex()
        p = PROGRESSES['strong-custody']['progress']
        for key, value in [('receipt_sha256', 'f'*64), ('witness_id', None), ('retain_until', m['prepared_at'])]:
            altered = copy.deepcopy(p); altered['custody'][key] = value; self.rejected(c.encode_progress, altered, m, h)
        a = A.copy(); a['custody_witness_verified'] = False
        self.rejected(c.transition, p, PROGRESSES['strong-intent']['progress'], m, h, 'ack', a)
        c.ack_allowed(PROGRESSES['m1-intent']['progress'], self.m, A)
        self.rejected(c.ack_allowed, PROGRESSES['strong-full']['progress'], m, A)

    def test_retirement_blocks_side_effects_and_needs_synced_removal(self):
        old = PROGRESSES['retire-intent']['progress']; new = copy.deepcopy(PROGRESSES['retired']['progress'])
        a = A.copy(); a['reclaim_files_deleted_and_synced'] = False
        self.rejected(c.transition, old, new, self.m, self.h, 'retire', a)
        new = copy.deepcopy(PROGRESSES['duplicate-intent']['progress']); new['revision'] = old['revision']+1; new['previous_sha256'] = bytes.fromhex(PROGRESSES['retire-intent']['wire_hex'])[-32:].hex(); new['retirement'] = old['retirement']
        self.rejected(c.transition, old, new, self.m, self.h, 'ack', A)
        new = copy.deepcopy(PROGRESSES['retired']['progress']); new['retirement']['observed_at'] = self.m['prepared_at']
        self.rejected(c.encode_progress, new, self.m, self.h)

    def test_reclaim_requires_nanosecond_horizon_and_known_history(self):
        p = PROGRESSES['confirmed']['progress']; horizon = self.m['retention']['retain_until']
        c.reclaim_allowed(p, self.m, horizon, A)
        self.rejected(c.reclaim_allowed, p, self.m, '2026-10-08T12:00:00.999999999Z', A)
        for key in ['fresh_grant', 'exclusive_owner', 'history_known']:
            a = A.copy(); a[key] = False; self.rejected(c.reclaim_allowed, p, self.m, horizon, a)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReceiptContractTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    print(json.dumps({'schema_version': 1, 'status': 'passed' if result.wasSuccessful() else 'failed', 'scope': 'offline_negative_and_relational_checks_only', 'tests': result.testsRun, 'rejection_checks': REJECTIONS, 'failures': len(result.failures), 'errors': len(result.errors)}, sort_keys=True))
    raise SystemExit(not result.wasSuccessful())

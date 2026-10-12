#!/usr/bin/env python3
"""Logical-delivery guards for the real saturated-spool recovery fixture."""
import copy
import importlib.util
from pathlib import Path
import unittest
import uuid

spec = importlib.util.spec_from_file_location('agent_process', Path(__file__).resolve().parents[1] / 'tests/integration/phase6-process.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class LogicalDelivery(unittest.TestCase):
    def event(self, message='original'):
        return {'id': str(uuid.uuid4()), 'message': message, 'attributes': {'nested': [True, 1844674407370955161600001]}}

    def test_exact_identity_and_nested_payload_replay_is_one_logical_event(self):
        event = self.event()
        result = fixture.logical_events([event, copy.deepcopy(event)], {})
        self.assertEqual(result, {event['id']: event})
        self.assertEqual(fixture.logical_events([copy.deepcopy(event)], result), result)

    def test_changed_duplicate_or_previously_observed_payload_denies(self):
        original = self.event()
        changed = copy.deepcopy(original)
        changed['attributes']['nested'].append('changed')
        for events, known in [([original, changed], {}), ([changed], {original['id']: original})]:
            with self.assertRaisesRegex(AssertionError, 'canonical event payload'):
                fixture.logical_events(events, known)

    def test_new_id_for_same_message_is_not_deduplicated(self):
        events = [self.event(), self.event()]
        result = fixture.logical_events(events, {})
        self.assertEqual(len(result), 2)
        self.assertNotEqual(sorted(e['message'] for e in result.values()), ['original'])

    def test_missing_previously_delivered_event_denies(self):
        original = self.event()
        with self.assertRaisesRegex(AssertionError, 'disappeared'):
            fixture.logical_events([], {original['id']: original})

    def test_invalid_or_nil_identity_denies(self):
        for identity in [None, '', 'bad', str(uuid.UUID(int=0))]:
            event = self.event()
            event['id'] = identity
            with self.assertRaises((AssertionError, ValueError)):
                fixture.logical_events([event], {})


if __name__ == '__main__':
    unittest.main()

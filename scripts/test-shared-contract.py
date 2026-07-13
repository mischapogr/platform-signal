#!/usr/bin/env python3
"""Negative contract mutations; no database behavior is simulated here."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
SPEC=importlib.util.spec_from_file_location('shared_contract',Path(__file__).with_name('check-shared-contract.py'))
C=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(C)
class ContractGuards(unittest.TestCase):
    def setUp(self):
        self.value=json.loads(C.read(C.ROOT/'schemas/shared-control/v1.json'))
        self.sql=C.read(C.ROOT/'schemas/shared-control/001.sql')
    def bad(self, fragment):
        with self.assertRaisesRegex(ValueError,fragment):C.validate(self.value,self.sql)
    def test_current_contract(self):
        self.assertEqual(C.validate(self.value,self.sql)['failure_cases'],18)
    def test_wrong_checksum(self):
        self.sql+=b' ';self.bad('checksum')
    def test_missing_token_generation(self):
        self.value['token_fields'].remove('generation');self.bad('scope')
    def test_unbounded_queue(self):
        self.value['limits']['queued_commands']=0;self.bad('limits')
    def test_bool_not_resource_integer(self):
        self.value['limits']['pool_connections']=True;self.bad('limits')
    def test_expanding_ceiling(self):
        self.value['limits']['request_bytes']+=1;self.bad('limits')
    def test_deadline_order(self):
        self.value['limits']['operation_ms']=500;self.bad('ordering')
    def test_remote_call_in_transaction(self):
        self.value['operations']['commit']['network']=True;self.bad('transaction network')
    def test_checkpoint_without_outbox(self):
        self.value['operations']['commit']['atomic'].remove('outbox');self.bad('publication')
    def test_expired_renew_allowed(self):
        self.value['operations']['renew']['fence']='generation_owner_epoch';self.bad('unexpired')
    def test_notification_missing_attempt_fence(self):
        self.value['operations']['finish_notification']['fence']='generation_owner_epoch_unexpired';self.bad('attempt')
    def test_restore_without_current_authority(self):
        self.value['restore']['current_external_authority']=False;self.bad('restore')
    def test_automatic_schema_reset(self):
        self.value['migration']['automatic_reset']=True;self.bad('migration')
    def test_partition_feed_position_cannot_be_global_cursor(self):
        self.value['feed']['position']='partition_local';self.bad('feed')
    def test_missing_crash_case(self):
        self.value['failure_matrix'].pop();self.bad('matrix')
    def test_duplicate_crash_case(self):
        self.value['failure_matrix'][0]=copy.deepcopy(self.value['failure_matrix'][1]);self.bad('matrix')
    def test_nullable_claim_epoch_hole(self):
        self.sql=self.sql.replace(b'claim_epoch IS NOT NULL AND ',b'')
        self.value['schema_sql_sha256']=hashlib.sha256(self.sql).hexdigest();self.bad('NULL')
    def test_public_dml_grant(self):
        self.sql+=b'GRANT ALL ON SCHEMA signal_control TO PUBLIC;'
        self.value['schema_sql_sha256']=hashlib.sha256(self.sql).hexdigest();self.bad('grant')
    def test_missing_exact_feed_digest(self):
        self.value['feed']['digest']='reserialized_json';self.bad('chain')
    def test_zero_prepared_must_not_advance_feed(self):
        self.value['receipt_only']['advances_feed']=True;self.bad('metadata-only')
    def test_global_finding_id_guard(self):
        self.sql=self.sql.replace(b'    UNIQUE (id),',b'')
        self.value['schema_sql_sha256']=hashlib.sha256(self.sql).hexdigest();self.bad('DDL')
    def test_restore_fence_removed(self):
        self.value['operations']['restore']['fence']='none';self.bad('obligations')
    def test_notification_intent_removed(self):
        self.value['operations']['claim_notification']['atomic']=['capacity'];self.bad('obligations')
    def test_receipt_checkpoint_substitution(self):
        self.value['operations']['record_receipt']['atomic']=['checkpoint'];self.bad('obligations')
    def test_missing_global_deduplication(self):
        self.value['feed'].pop('deduplication');self.bad('deduplication')
    def test_missing_tombstone_identity(self):
        self.value.pop('tombstone_identity');self.bad('retirement')
    def test_duplicate_json_fields(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):
            json.loads('{"revision":1,"revision":2}',object_pairs_hook=C.unique_object)
    def test_cap_before_read(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'oversized';path.write_bytes(b'x'*(C.CAP+1))
            with self.assertRaisesRegex(ValueError,'capacity'):C.read(path)
if __name__=='__main__':unittest.main()

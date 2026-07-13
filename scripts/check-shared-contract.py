#!/usr/bin/env python3
"""Validate finite Standard control contract; this does not qualify runtime."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
CAP = 64 * 1024
TOKENS = ['store_id', 'generation', 'tenant', 'stream', 'partition_id', 'owner', 'epoch']
TABLES = ['store', 'partitions', 'commits', 'receipts', 'state', 'findings', 'outbox', 'snapshots', 'tombstones']
FAILURES = {
    'upload_before_commit_crash': 'orphan_only_no_checkpoint',
    'transaction_before_commit_crash': 'rollback_all',
    'commit_reply_lost': 'resolve_exact_request_or_remain_uncertain',
    'owner_expired_before_transaction': 'reject_no_mutation',
    'owner_changes_after_upload': 'reject_no_mutation_orphan_only',
    'owner_stalls_after_lock': 'transaction_timeout_rollback_then_takeover',
    'foreign_tenant_stream': 'reject_no_disclosure',
    'request_id_conflicting_payload': 'reject_no_mutation',
    'quota_at_commit': 'whole_transaction_rejected',
    'notification_accepted_reply_lost': 'same_key_payload_uncertain_retry',
    'old_attempt_finishes_after_takeover': 'reject_no_mutation',
    'snapshot_expired': 'fail_no_partial_results',
    'gc_old_owner_or_reachable_object': 'reject_no_delete',
    'old_backup_restored': 'new_generation_old_tokens_rejected',
    'object_missing_on_restore': 'remain_not_ready_no_reconstruction',
    'unknown_or_newer_schema': 'fail_no_automatic_reset',
    'cancelled_transaction_or_pool_full': 'bounded_failure_no_false_success',
    'zero_prepared_quarantined_receipt': 'metadata_only_no_fake_manifest_checkpoint_or_feed',
}
OPS = {'record_receipt', 'initialize', 'acquire', 'renew', 'commit', 'read_snapshot', 'claim_notification',
       'finish_notification', 'retire', 'restore', 'migrate'}
REQUIRED_OPS = {
    'initialize': ('administrator', 'explicit_empty_schema', ['identity','generation','schema_revision','capacity']),
    'acquire': ('runtime', 'generation_and_expired_owner', ['epoch_increment','owner','lease']),
    'renew': ('runtime', 'generation_owner_epoch_unexpired', ['lease']),
    'commit': ('runtime', 'generation_owner_epoch_unexpired', ['manifest','checkpoint','rule_state','findings','feed_position','outbox','receipt_progress','capacity']),
    'read_snapshot': ('runtime', 'trusted_scope_and_generation', ['bounded_snapshot_pin']),
    'claim_notification': ('private_adapter', 'generation_owner_epoch_unexpired', ['attempt_id','delivery_intent','capacity']),
    'finish_notification': ('private_adapter', 'generation_owner_epoch_unexpired_and_attempt', ['delivery_status']),
    'retire': ('runtime', 'generation_owner_epoch_unexpired_and_no_readers', ['logical_retirement','irrevocable_tombstone','capacity']),
    'restore': ('administrator', 'stopped_writers_and_current_external_authority', ['new_generation','leases_revoked','attempts_uncertain','restore_checkpoint','ready_false']),
    'migrate': ('administrator', 'stopped_writers_and_exact_revision_checksum', ['schema_revision','migration']),
    'record_receipt': ('runtime', 'generation_owner_epoch_unexpired', ['receipt_reference','disposition_pins','capacity']),
}
MAXIMA = {'request_bytes':1048576, 'reply_bytes':1048576, 'pool_connections':4,
    'queued_commands':32, 'partitions':128, 'rows':65536, 'metadata_bytes':67108864,
    'transaction_ms':2000, 'lock_ms':500, 'operation_ms':5000, 'lease_ms':15000,
    'lease_max_ms':60000, 'batch_records':4096, 'batch_findings':128,
    'batch_state':128, 'batch_deliveries':128, 'manifest_bytes':262144,
    'state_bytes':65536, 'finding_bytes':65536, 'plan_bytes':65536,
    'reference_bytes':65536, 'snapshot_objects':128, 'snapshot_ms':5000,
    'attempts':10, 'retry_rounds':3}


def read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular contract file required')
    with path.open('rb') as stream:
        data = stream.read(CAP + 1)
    if len(data) > CAP:
        raise ValueError('contract file capacity')
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate contract field')
        result[key] = value
    return result


def validate(value, sql):
    if value.get('schema_version') != 1 or type(value.get('schema_version')) is not int or value.get('backend') != 'postgresql' or value.get('minimum_major') != 17:
        raise ValueError('contract identity/backend')
    if value.get('schema_sql_sha256') != hashlib.sha256(sql).hexdigest():
        raise ValueError('migration checksum')
    if value.get('token_fields') != TOKENS or value.get('schema_tables') != TABLES:
        raise ValueError('trusted token/schema scope')
    limits = value.get('limits', {})
    if set(limits) != set(MAXIMA) or any(type(limits[k]) is not int or not 0 < limits[k] <= cap for k,cap in MAXIMA.items()):
        raise ValueError('finite limits')
    if not limits['lock_ms'] < limits['transaction_ms'] < limits['operation_ms'] < limits['lease_ms'] <= limits['lease_max_ms']:
        raise ValueError('deadline ordering')
    operations = value.get('operations', {})
    if set(operations) != OPS or any(type(op.get('network')) is not bool or op['network'] for op in operations.values()):
        raise ValueError('finite operations/no transaction network')
    for name, op in operations.items():
        if set(op) != {'actor','fence','atomic','network'} or not isinstance(op['atomic'], list) or not op['atomic'] or len(op['atomic']) > 10 or len(set(op['atomic'])) != len(op['atomic']):
            raise ValueError('operation shape')
        if name in ('initialize','restore','migrate'):
            if op['actor'] != 'administrator':
                raise ValueError('administrative boundary')
        elif name in ('claim_notification','finish_notification'):
            if op['actor'] != 'private_adapter':
                raise ValueError('private adapter boundary')
        elif op['actor'] != 'runtime':
            raise ValueError('runtime boundary')
    if operations['acquire']['fence'] != 'generation_and_expired_owner' or operations['acquire']['atomic'] != ['epoch_increment','owner','lease']:
        raise ValueError('monotonic ownership')
    for name in ('renew','commit','claim_notification','record_receipt'):
        if operations[name]['fence'] != 'generation_owner_epoch_unexpired':
            raise ValueError('current unexpired ownership')
    if operations['finish_notification']['fence'] != 'generation_owner_epoch_unexpired_and_attempt':
        raise ValueError('attempt fencing')
    if operations['commit']['atomic'] != ['manifest','checkpoint','rule_state','findings','feed_position','outbox','receipt_progress','capacity']:
        raise ValueError('atomic publication boundary')
    if operations['retire']['fence'] != 'generation_owner_epoch_unexpired_and_no_readers':
        raise ValueError('reader/retirement fence')
    if value.get('migration') != {'revision':1,'explicit_only':True,'unknown_revision':'reject','checksummed':True,'automatic_reset':False,'downgrade':'stopped_restore_only'}:
        raise ValueError('explicit migration')
    if value.get('restore') != {'new_generation':True,'current_external_authority':True,'old_tokens':'reject','replay':'retained_exact_pins_only','redetection':'explicit_only','object_versions_required':True}:
        raise ValueError('coordinated current-authority restore')
    if value.get('feed', {}).get('stream_identity') != 'store_id' or value['feed'].get('position') != 'globally_monotonic_bigint':
        raise ValueError('global findings feed identity')
    if value['feed'].get('retention') != 'no feed pruning in revision1; quota failure preserves complete chain' or value['feed'].get('digest') != 'existing FindingsCursor::advance over exact first-occurrence payload bytes':
        raise ValueError('exact feed chain history')
    if value.get('receipt_only', {}).get('advances_checkpoint') is not False or value['receipt_only'].get('advances_feed') is not False:
        raise ValueError('metadata-only receipt boundary')
    for name, (actor, fence, atomic) in REQUIRED_OPS.items():
        if operations[name]['actor'] != actor or operations[name]['fence'] != fence or operations[name]['atomic'] != atomic:
            raise ValueError('complete operation obligations')
    feed = value['feed']
    if feed.get('deduplication') != 'global finding id; exact bytes replay no position or delivery advance' or feed.get('restore') != 'retain exact historical chain and attempt evidence; reconcile every dependent consumer cursor before readiness':
        raise ValueError('global feed deduplication/restore')
    receipt = value['receipt_only']
    if receipt.get('commit_id') != 'nullable only while retained or zero prepared' or receipt.get('zero_prepared') != 'explicit disposition and source-policy/custody authorization; no implicit ACK' or receipt.get('prepared_count') != '0..4096' or receipt.get('source_record_count') != '0..4096':
        raise ValueError('complete zero-prepared receipt obligations')
    if value.get('tombstone_identity') != 'canonical backend id + object key + exact version, globally unique across partitions':
        raise ValueError('global retirement identity')
    cases = value.get('failure_matrix', [])
    if len(cases) != len(FAILURES) or any(set(c) != {'id','expected'} for c in cases) or len({c['id'] for c in cases}) != len(cases) or {c['id']:c['expected'] for c in cases} != FAILURES:
        raise ValueError('finite failure matrix')
    text = re.sub(r'--[^\n]*', '', sql.decode('utf-8'))
    if re.findall(r'CREATE TABLE signal_control\.([a-z_]+)', text) != TABLES:
        raise ValueError('DDL table inventory')
    required = ['BEGIN;', 'COMMIT;', 'REVOKE ALL ON SCHEMA signal_control FROM PUBLIC;',
        'REVOKE ALL ON ALL TABLES IN SCHEMA signal_control FROM PUBLIC;',
        'used_rows <= max_rows', 'used_bytes <= max_bytes', 'UNIQUE (position)', 'UNIQUE (id)',
        'feed_digest bytea NOT NULL', 'cursor_digest bytea NOT NULL',
        'prepared_count BETWEEN 0 AND 4096', "commit_id IS NOT NULL OR state = 'retained' OR prepared_count = 0",
        'UNIQUE (reference_sha256)',
        'UNIQUE (partition_id, first_sequence)', 'claim_epoch IS NOT NULL',
        'FOREIGN KEY (partition_id, previous)', 'FOREIGN KEY (partition_id, commit_id)',
        'FOREIGN KEY (partition_id, finding_id)', "CHECK (status <> 'intent' OR attempt_id IS NOT NULL)"]
    if any(clause not in text for clause in required):
        raise ValueError('DDL bounded/key/NULL/privilege guard')
    if re.search(r'\b(DROP|TRUNCATE|COPY|DELETE|INSERT|UPDATE|GRANT)\b', text, re.I):
        raise ValueError('DDL must not initialize/reset/grant runtime authority')
    return {'status':'passed_local','scope':'finite contract checks only; no runtime/HA acceptance',
            'tables':len(TABLES),'operations':len(OPS),'failure_cases':len(FAILURES),
            'schema_sql_sha256':value['schema_sql_sha256']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args=parser.parse_args()
    contract=json.loads(read(ROOT/'schemas/shared-control/v1.json'), object_pairs_hook=unique_object)
    report=validate(contract, read(ROOT/'schemas/shared-control/001.sql'))
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open('x') as stream:
            json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps(report))

if __name__=='__main__':
    main()

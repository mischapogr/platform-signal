#!/usr/bin/env python3
"""Negative acceptance guards for the real PostgreSQL fixture launcher."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('shared_runtime',ROOT/'scripts/check-shared-runtime.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
GOOD="""phase: atomic-original-scoped-publication-facts-counters-and-startup-fencing-qualified
phase: current-finding-scope-activation-enrollment-counters-and-authority-qualified
phase: shared-finding-scope-stopped-schema-and-immutable-prefix-qualified
phase: globally-authorized-original-feed-qualified
phase: populated-multi-event-and-history-restore-real-Parquet-omission-corruption-custody-and-fresh-generation-qualified
phase: multi-event-administrative-and-readonly-producer-inspection-qualified
phase: multi-event-scoped-reader-paired-grants-privileges-and-corruption-qualified
phase: bounded-multi-event-client-original-commit-replay-and-fencing-qualified
phase: bounded-multi-event-client-module-identity-and-drift-refusal-qualified
phase: protected-prior-state-multi-event-references-qualified
phase: atomic-multi-event-publication-replay-quota-and-late-rollback-qualified
phase: stopped-additive-multi-event-installation-qualified
phase: fenced-revisioned-state-recovery-read-qualified
phase: pinned-canonical-recovery-bounds-and-missing-evidence-qualified
phase: recovered-state-object-retention-replay-and-fencing-qualified
phase: globally-authorized-restored-feed-qualified
phase: coordinated-stopped-restore-qualification-complete
phase: dynamic-catalog-and-stopped-profile-qualification-complete
phase: shared-catalog-actual-parquet-query-composition-complete
phase: coordinated-catalog-restore-and-actual-query-qualified
phase: administrative-migration-qualification-complete
phase: notification-fencing-qualification-complete
phase: exact-version-retirement-qualification-complete
phase: bounded-snapshot-qualification-complete
phase: atomic-publication-qualification-complete
running 1 test
test postgres_lease_authority_and_cancellation ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 3.83s
"""
class Guards(unittest.TestCase):
    def test_window_report_requires_original_ids_revision_all_cases_and_finite_resources(self):
        names=['Standard_WINDOW_explicit_bootstrap_and_enrolled_quota_mismatch_refused',
        'Standard_WINDOW_missing_pin_permission_startup_refused_original_state_unchanged',
        'Standard_WINDOW_revision_change_startup_refused_original_state_unchanged',
               'Standard_WINDOW_Main_blocked_publication_SIGKILL_original_request_claims_once_recovered',
               'Standard_WINDOW_same_timestamp_split_batches_wait_for_source_watermark',
               'Standard_WINDOW_protected_delayed_anchor_and_exact_retry_original_findings',
               'Standard_WINDOW_SIGKILL_confirmed_original_state_history_checkpoint',
               'Standard_WINDOW_Main_restart_duplicate_Parquet_original_sequence_scope_bytes_and_replay_pins']
        report={'status':'passed_simulated','window_qualified':True,'binary_sha256':'a'*64,
                'wal_checkpoint':6,'child_capacity':3,'log_capacity':24,'provider_calls':12,
                'event_ids':['00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002'],
                'scenarios':[{'name':n} for n in names]}
        module.qualify_standard_window_report(report,'a'*64)
        for key,value in [('status','passed'),('window_qualified',False),('binary_sha256','b'*64),
            ('wal_checkpoint',4),('child_capacity',4),('provider_calls',129),('event_ids',[report['event_ids'][0]]*2),
            ('event_ids',['invalid',report['event_ids'][1]]),('scenarios',[{'name':names[0]}]*4)]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                module.qualify_standard_window_report({**report,key:value},'a'*64)

    def test_onboarding_selector_refuses_unfocused_and_kubernetes_campaigns_before_side_effects(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'must-not-exist'
            for options in [[],['--standard'],['--standard-only','--standard-kubernetes-image','fixture']]:
                result=subprocess.run(['python3',str(ROOT/'scripts/check-shared-runtime.py'),'--standard-scenario','onboarding','--output',str(output),*options],capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,2)
                self.assertIn('--standard-scenario onboarding requires',result.stderr)
                self.assertFalse(output.exists())

    def test_combined_standard_budget_preserves_separate_limits_and_rejects_overflow(self):
        self.assertFalse(module.elapsed_within_fixture_budget(240.001))
        self.assertTrue(module.elapsed_within_fixture_budget(240.001,combined_standard=True))
        self.assertTrue(module.elapsed_within_fixture_budget(420,combined_standard=True))
        for value in (-1,420.001,float('inf'),float('nan'),True,'420'):
            with self.subTest(value=value):
                self.assertFalse(module.elapsed_within_fixture_budget(value,combined_standard=True))
        for mode in (None,1,'true'):
            self.assertFalse(module.elapsed_within_fixture_budget(1,combined_standard=mode))

    def test_standard_private_requires_actual_notifications_and_original_event_bindings(self):
        events=['00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002']
        good={'schema_version':1,'status':'passed_simulated','binary_sha256':'a'*64,'child_capacity':3,'log_capacity':24,
              'provider_calls':4,'private_original_cursor_restart_qualified':True,'populated_scope_restore_stage_qualified':True,'raw_feed_sha256':'b'*64,
              'notification_calls':6,'notification_deliveries':2,'event_ids':events,'notification_witness_sha256':'c'*64,'private_binary_sha256':'d'*64,
              'scenarios':[{'name':'actual_Standard_native_feed_private_atomic_outbox_exact_replay_three_attempt_notifications','status':'passed_simulated','event_ids':events},
                           {'name':'actual_Standard_original_feed_cursor_private_restart_no_historical_redelivery','status':'passed_simulated'}]}
        module.qualify_standard_private_report(good,'a'*64)
        for key,value in [('populated_scope_restore_stage_qualified',False),('private_original_cursor_restart_qualified',False),('notification_calls',5),('notification_calls',7),
                          ('notification_deliveries',1),('binary_sha256','b'*64),('provider_calls',0),('child_capacity',4),
                          ('raw_feed_sha256','bad'),('private_binary_sha256','bad'),('notification_witness_sha256',None),('event_ids',events[:1]),('event_ids',[events[0]]*2),
                          ('scenarios',good['scenarios'][::-1]),('scenarios',good['scenarios'][:1])]:
            with self.assertRaises(ValueError):module.qualify_standard_private_report(dict(good,**{key:value}),'a'*64)

    def test_standard_restore_requires_fresh_generation_original_progress_and_new_publication(self):
        events=['00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002']
        event='00000000-0000-0000-0000-000000000003'
        receipt={'schema_version':1,'generation':'00000000-0000-0000-0000-000000000005',
                 'old_generation':'00000000-0000-0000-0000-000000000004','ready':True,
                 'scope_original_bytes_preserved':True,'consumer_current_reconciled':True,
                 'scoped_ddl_error_rollback':True,'scoped_ddl_cancel_rollback':True,'scoped_lost_commit_resolved':True,'scoped_consumer_resume_refused':True,
                 'inventory':{'old_generation':'00000000-0000-0000-0000-000000000004','feed_position':2,
                              'revision':4,'objects':[{}],'consumers':[{'position':2}]}}
        good={'schema_version':1,'status':'passed_simulated','binary_sha256':'a'*64,'child_capacity':3,'log_capacity':24,
              'provider_calls':4,'private_original_cursor_restart_qualified':True,'populated_scope_restore_stage_qualified':True,
              'raw_feed_sha256':'b'*64,'notification_calls':6,'notification_deliveries':2,'event_ids':events,
              'notification_witness_sha256':'c'*64,'private_binary_sha256':'d'*64,
              'scoped_restore_generation_qualified':True,'restored_retirement_qualified':True,'restored_native_publication_qualified':True,
              'restore_receipt':receipt,'restored_event_id':event,'old_generation_Main_fenced':True,'original_source_checkpoint_unchanged':True,
              'scenarios':[{'name':'actual_Standard_native_feed_private_atomic_outbox_exact_replay_three_attempt_notifications','status':'passed_simulated','event_ids':events},
                           {'name':'actual_Standard_fresh_destination_generation_original_cursor_restart_and_new_native_publication','status':'passed_simulated','event_id':event}]}
        module.qualify_standard_restore_report(good,'a'*64)
        for key,value in [('scoped_restore_generation_qualified',False),('restored_native_publication_qualified',False),
                          ('restored_retirement_qualified',False),('old_generation_Main_fenced',False),('original_source_checkpoint_unchanged',False),('restored_event_id',events[0]),('restored_event_id',None),('scenarios',[None,None]),('notification_calls',7)]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):module.qualify_standard_restore_report(dict(good,**{key:value}),'a'*64)
        for key,value in [('generation',receipt['old_generation']),('old_generation',None),('ready',False),
                          ('scope_original_bytes_preserved',False),('consumer_current_reconciled',False),('scoped_ddl_error_rollback',False),
                          ('scoped_ddl_cancel_rollback',False),('scoped_lost_commit_resolved',False),('scoped_consumer_resume_refused',False),('inventory',{})]:
            with self.subTest(receipt=key):
                with self.assertRaises(ValueError):module.qualify_standard_restore_report(dict(good,restore_receipt=dict(receipt,**{key:value})),'a'*64)

    def test_standard_audit_requires_exact_scenarios_original_identities_and_bounds(self):
        good={'schema_version':1,'status':'passed_simulated','binary_sha256':'a'*64,'child_capacity':3,'log_capacity':24,
              'independent_receiver_qualified':True,'exact_pending_replay_qualified':True,'empty_WAL_qualified':True,
              'provider_calls':2,'required_audit_failure_seconds':0.1,'original_pending_sha256':'b'*64,
              'audit_producer_id':'00000000-0000-0000-0000-000000000009',
              'audit_record_ids':[f'00000000-0000-0000-0000-{i:012d}' for i in range(1,6)],
              'scenarios':[{'name':name,'status':'passed_simulated'} for name in (
                  'actual_Standard_activation_receipts_before_ready_independent_receiver_survives_stop',
                  'actual_Standard_required_audit_outage_holds_with_original_pending_receipt',
                  'actual_Standard_original_audit_replay_fresh_activations_existing_receiver_empty_WAL')]}
        module.qualify_standard_audit_report(good,'a'*64)
        for key,value in [('binary_sha256','b'*64),('exact_pending_replay_qualified',False),('independent_receiver_qualified',False),
                          ('empty_WAL_qualified',False),('child_capacity',4),('log_capacity',25),('provider_calls',65),
                          ('required_audit_failure_seconds',float('nan')),('required_audit_failure_seconds',7),
                          ('audit_record_ids',good['audit_record_ids'][:4]),('audit_record_ids',[good['audit_record_ids'][0]]*5),
                          ('audit_producer_id','00000000-0000-0000-0000-000000000000'),('original_pending_sha256','bad'),
                          ('scenarios',good['scenarios'][:2]),('scenarios',good['scenarios'][::-1])]:
            with self.assertRaises(ValueError):module.qualify_standard_audit_report(dict(good,**{key:value}),'a'*64)

    def test_standard_binary_snapshot_survives_default_cargo_output_replacement(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'server';destination=root/'qualified-server'
            source.write_bytes(b'all-feature executable fixture')
            digest=module.capture_standard_binary(source,destination)
            source.write_bytes(b'default executable fixture')
            self.assertEqual(destination.read_bytes(),b'all-feature executable fixture')
            self.assertEqual(digest,hashlib.sha256(destination.read_bytes()).hexdigest())
            with self.assertRaises(ValueError):module.capture_standard_binary(source,destination)
            link=root/'link';link.symlink_to(source)
            with self.assertRaises(ValueError):module.capture_standard_binary(link,root/'absent')
            source.write_bytes(b'')
            with self.assertRaises(ValueError):module.capture_standard_binary(source,root/'absent')
    def test_standard_report_requires_exact_runtime_binary_cases_and_witnesses(self):
        good={'schema_version':1,'status':'passed_simulated','producer_credentials_qualified':True,
              'original_publication_crash_recovery_qualified':True,'unprepared_native_wal_hold_qualified':True,
              'pending_native_event_id':'12345678-1234-1234-1234-123456789016','child_capacity':3,'log_capacity':24,
              'original_crash_event_id':'12345678-1234-1234-1234-123456789014','original_crash_request_id':'12345678-1234-1234-1234-123456789015',
              'startup_denials':['owner-capable-producer','direct-reader-as-producer'],
              'empty_catalog_qualified':True,'selected_coverage_startup_and_restart_qualified':True,'missing_coverage_failure_qualified':True,'missing_coverage_failure_seconds':.2,'invalid_cache_failure_qualified':True,'invalid_cache_failure_seconds':.2,'late_startup_failure_qualified':True,'late_startup_failure_seconds':.2,'startup_interruption_qualified':True,'startup_interruption_seconds':.2,'provider_calls':13,'binary_sha256':'a'*64,
              'scenarios':[{'name':'actual_Standard_native_TLS_ingest_versioned_S3_query_scoped_findings_global_feed_graceful_shutdown',
                            'status':'passed_simulated','event_ids':['12345678-1234-1234-1234-123456789012','12345678-1234-1234-1234-123456789013']},
                           {'name':'actual_Standard_stopped_original_WAL_explicit_holds_exact_retirement_stale_fence','status':'passed_simulated'},
                          {'name':'actual_Standard_stopped_restart_original_enrollment_and_current_query','status':'passed_simulated'},
                           {'name':'actual_Standard_SIGKILL_saved_original_request_manifest_once_checkpoint3','status':'passed_simulated',
                            'event_id':'12345678-1234-1234-1234-123456789014','request_id':'12345678-1234-1234-1234-123456789015'},
                           {'name':'actual_Standard_unprepared_native_WAL_restart_held_original_row_checkpoint3','status':'passed_simulated',
                            'event_id':'12345678-1234-1234-1234-123456789016'}]}
        module.qualify_standard_report(good,'a'*64)
        for key,value in [('unprepared_native_wal_hold_qualified',False),('pending_native_event_id','bad'),
                          ('original_publication_crash_recovery_qualified',False),('child_capacity',4),('log_capacity',32),
                          ('original_crash_event_id','bad'),('original_crash_request_id','bad'),('status','passed_local'),('producer_credentials_qualified',False),('empty_catalog_qualified',None),('selected_coverage_startup_and_restart_qualified',False),('missing_coverage_failure_qualified',False),
                          ('missing_coverage_failure_seconds',5),('missing_coverage_failure_seconds',True),
                          ('provider_calls',True),('provider_calls',65),('binary_sha256','b'*64),('scenarios',[]),
                          ('scenarios',[good['scenarios'][0]]*2),('startup_denials',[]),
                          ('scenarios',good['scenarios'][:1]+good['scenarios'][2:]),
                          ('scenarios',good['scenarios'][:1]+[good['scenarios'][0]]+good['scenarios'][2:]),
                          ('invalid_cache_failure_qualified',False),('invalid_cache_failure_seconds',5),
                          ('invalid_cache_failure_seconds',True),('late_startup_failure_qualified',False),('late_startup_failure_seconds',5),
                          ('late_startup_failure_seconds',True),('startup_interruption_qualified',False),('startup_interruption_seconds',3),
                          ('startup_interruption_seconds',True)]:
            with self.assertRaises(ValueError):module.qualify_standard_report(dict(good,**{key:value}),'a'*64)
        for identifiers in ([good['scenarios'][0]['event_ids'][0]]*2,['','bad'],[{},None],['00000000-0000-0000-0000-000000000000',good['scenarios'][0]['event_ids'][1]]):
            bad=json.loads(json.dumps(good));bad['scenarios'][0]['event_ids']=identifiers
            with self.assertRaises(ValueError):module.qualify_standard_report(bad,'a'*64)
        with self.assertRaises(ValueError):module.qualify_standard_report(None,'a'*64)
    def test_final_elapsed_uses_the_expanded_execution_budget(self):
        # A complete run beyond the old180s limit must not be rejected after
        # execution was explicitly admitted within the expanded240s budget.
        for elapsed in (0, 180.5, 239.9, 240):
            self.assertTrue(module.elapsed_within_fixture_budget(elapsed))
        for elapsed in (-1, 240.001, float('inf'), float('-inf'), float('nan'), True, '240'):
            self.assertFalse(module.elapsed_within_fixture_budget(elapsed))

    def test_readiness_wait_has_finite_probes_and_rejects_invalid_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            probe=directory/'pg_isready'
            probe.write_text(r'''#!/usr/bin/python3
import json, os, pathlib, sys
p=pathlib.Path(os.environ['READY_TRACE'])
calls=p.read_text().splitlines() if p.exists() else []
p.write_text('\n'.join(calls+[json.dumps(sys.argv[1:])])+'\n')
codes=json.loads(os.environ['READY_CODES'])
sys.exit(codes[min(len(calls),len(codes)-1)])
''')
            probe.chmod(0o700)
            pause=directory/'sleep'
            pause.write_text('#!/bin/sh\nexit 0\n')
            pause.chmod(0o700)
            trace=directory/'trace'
            for codes,status,count,limit in [([2,1,0],0,3,None),([2],1,60,None),([3],3,1,None),
                                            ([2]*74+[0],0,75,'120'),([2],1,120,'120'),
                                            ([0],3,0,'121'),([0],3,0,'0')]:
                with self.subTest(codes=codes,limit=limit):
                    trace.unlink(missing_ok=True)
                    argv=['sh','-c',module.READY_SCRIPT]
                    if limit is not None:argv.extend(['signal-ready-fixture',limit])
                    result=subprocess.run(argv,
                        env=dict(os.environ,PATH=str(directory)+os.pathsep+os.environ['PATH'],
                                 READY_TRACE=str(trace),READY_CODES=json.dumps(codes)),
                        capture_output=True,text=True,timeout=6)
                    self.assertEqual(result.returncode,status,result.stderr)
                    calls=[json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
                    self.assertEqual(len(calls),count)
                    self.assertTrue(all(call==['-q','-t','1','-h','127.0.0.1','-U','postgres'] for call in calls))
    def test_all_eighteen_cases_required(self):
        import json
        ids=[case['id'] for case in json.loads((ROOT/'schemas/shared-control/v1.json').read_text())['failure_matrix']]
        evidence=GOOD+'phase: crash-marker-atomic-publication-qualified\nphase: abrupt-process-crash-qualification-complete\n'+''.join(f'matrix-case:{case} passed\n' for case in ids)
        self.assertEqual(len(module.qualify_matrix_output(evidence)),18)
        for case in ids:
            with self.subTest(missing=case),self.assertRaises(ValueError):
                module.qualify_matrix_output(evidence.replace(f'matrix-case:{case} passed\n',''))
            with self.subTest(duplicate=case),self.assertRaises(ValueError):
                module.qualify_matrix_output(evidence+f'matrix-case:{case} passed\n')
        for altered in (evidence.replace('phase: crash-marker-atomic-publication-qualified\n',''),evidence+'phase: crash-marker-atomic-publication-qualified\n',evidence+'matrix-case:unknown passed\n',evidence.replace('phase: abrupt-process-crash-qualification-complete\n',''),evidence+'phase: abrupt-process-crash-qualification-complete\n'):
            with self.assertRaises(ValueError):module.qualify_matrix_output(altered)
    def test_restart_probe_requires_exact_execution(self):
        good="phase: current-finding-scope-original-host-authority-after-restart-qualified\nphase: shared-finding-scope-persistent-restart-original-authority-qualified\nphase: persistent-restored-global-feed-qualified\nphase: persistent-catalog-restored-query-qualified\nphase: persistent-catalog-restart-fresh-client-qualified\nphase: persistent-restart-fresh-client-qualified\nrunning 1 test\ntest postgres_matrix_restart_probe ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.20s\n"
        module.qualify_restart_probe(good)
        for output in (good+good,good.replace('running 1 test','running 0 tests'),good.replace('1 passed; 0 failed','0 passed; 1 failed'),good.replace(' ... ok',' ... ignored'),good.replace('phase: persistent-restart-fresh-client-qualified\n',''),good+'test result: ok. 0 passed; 0 failed\n',good+'x'*65537):
            with self.assertRaises(ValueError):module.qualify_restart_probe(output)
    def test_restart_witness_requires_all_six_complete_databases(self):
        good={'postgres':'a'*64,'signal_restore_destination':'b'*64,'signal_catalog_profile':'c'*64,'signal_catalog_restore_source':'d'*64,'signal_catalog_restore_destination':'e'*64,'signal_finding_scope_fixture':'f'*64}
        module.qualify_restart_witness(good,good.copy())
        for after in ({},{'postgres':'a'*64},{'postgres':'a'*64,'signal_restore_destination':'b'*64},dict(good,postgres='c'*64),dict(good,extra='d'*64)):
            with self.assertRaises(ValueError):module.qualify_restart_witness(good,after)
        for value in ('', 'x'*64, 'a'*63, None):
            bad=dict(good,postgres=value)
            with self.assertRaises(ValueError):module.qualify_restart_witness(bad,bad.copy())
        missing=dict(good)
        missing.pop('signal_finding_scope_fixture')
        with self.assertRaises(ValueError):module.qualify_restart_witness(missing,missing.copy())
    def test_exact_executed_fixture_passes(self):
        module.qualify_test_output(GOOD)
    def test_global_feed_and_restored_markers_require_exact_execution(self):
        for marker in ('phase: populated-multi-event-and-history-restore-real-Parquet-omission-corruption-custody-and-fresh-generation-qualified\n', 'phase: multi-event-administrative-and-readonly-producer-inspection-qualified\n', 'phase: multi-event-scoped-reader-paired-grants-privileges-and-corruption-qualified\n', 'phase: bounded-multi-event-client-original-commit-replay-and-fencing-qualified\n', 'phase: bounded-multi-event-client-module-identity-and-drift-refusal-qualified\n', 'phase: protected-prior-state-multi-event-references-qualified\n', 'phase: atomic-multi-event-publication-replay-quota-and-late-rollback-qualified\n', 'phase: stopped-additive-multi-event-installation-qualified\n', 'phase: recovered-state-object-retention-replay-and-fencing-qualified\n', 'phase: pinned-canonical-recovery-bounds-and-missing-evidence-qualified\n', 'phase: fenced-revisioned-state-recovery-read-qualified\n', 'phase: globally-authorized-original-feed-qualified\n', 'phase: globally-authorized-restored-feed-qualified\n', 'phase: shared-finding-scope-stopped-schema-and-immutable-prefix-qualified\n'):
            for output in (GOOD.replace(marker, ''), GOOD + marker):
                with self.assertRaises(ValueError):module.qualify_test_output(output)
        good='phase: current-finding-scope-original-host-authority-after-restart-qualified\nphase: shared-finding-scope-persistent-restart-original-authority-qualified\nphase: persistent-restored-global-feed-qualified\nphase: persistent-catalog-restored-query-qualified\nphase: persistent-catalog-restart-fresh-client-qualified\nphase: persistent-restart-fresh-client-qualified\nrunning 1 test\ntest postgres_matrix_restart_probe ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.20s\n'
        module.qualify_restart_probe(good)
        for marker in ('phase: shared-finding-scope-persistent-restart-original-authority-qualified\n','phase: persistent-restored-global-feed-qualified\n'):
            for output in (good.replace(marker,''), good+marker):
                with self.assertRaises(ValueError):module.qualify_restart_probe(output)
    def test_atomic_scoped_publication_marker_requires_exact_execution(self):
        marker='phase: atomic-original-scoped-publication-facts-counters-and-startup-fencing-qualified\n'
        for output in (GOOD.replace(marker,''),GOOD+marker):
            with self.assertRaises(ValueError):
                module.qualify_test_output(output)

    def test_current_scope_host_api_markers_require_exact_execution(self):
        marker='phase: current-finding-scope-activation-enrollment-counters-and-authority-qualified\n'
        for output in (GOOD.replace(marker,''),GOOD+marker):
            with self.assertRaises(ValueError):module.qualify_test_output(output)
        good='phase: current-finding-scope-original-host-authority-after-restart-qualified\nphase: shared-finding-scope-persistent-restart-original-authority-qualified\nphase: persistent-restored-global-feed-qualified\nphase: persistent-catalog-restored-query-qualified\nphase: persistent-catalog-restart-fresh-client-qualified\nphase: persistent-restart-fresh-client-qualified\nrunning 1 test\ntest postgres_matrix_restart_probe ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.20s\n'
        module.qualify_restart_probe(good)
        marker='phase: current-finding-scope-original-host-authority-after-restart-qualified\n'
        for output in (good.replace(marker,''),good+marker):
            with self.assertRaises(ValueError):module.qualify_restart_probe(output)
    def test_missing_restore_qualification_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD.replace('phase: coordinated-stopped-restore-qualification-complete\n',''))
    def test_missing_or_duplicated_catalog_qualification_rejected(self):
        marker='phase: dynamic-catalog-and-stopped-profile-qualification-complete\n'
        for output in (GOOD.replace(marker,''),GOOD+marker):
            with self.assertRaises(ValueError):module.qualify_test_output(output)
    def test_missing_catalog_restart_cannot_close_gate(self):
        output="phase: persistent-restart-fresh-client-qualified\nrunning 1 test\ntest postgres_matrix_restart_probe ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.20s\n"
        with self.assertRaises(ValueError):module.qualify_restart_probe(output)
    def test_missing_or_duplicated_query_composition_rejected(self):
        marker='phase: shared-catalog-actual-parquet-query-composition-complete\n'
        for output in (GOOD.replace(marker,''),GOOD+marker):
            with self.assertRaises(ValueError):module.qualify_test_output(output)
    def test_catalog_restore_and_restart_cannot_be_missing_or_duplicated(self):
        marker='phase: coordinated-catalog-restore-and-actual-query-qualified\n'
        for output in (GOOD.replace(marker,''),GOOD+marker):
            with self.assertRaises(ValueError):module.qualify_test_output(output)
        restart='phase: current-finding-scope-original-host-authority-after-restart-qualified\nphase: shared-finding-scope-persistent-restart-original-authority-qualified\nphase: persistent-restored-global-feed-qualified\nphase: persistent-catalog-restored-query-qualified\nphase: persistent-catalog-restart-fresh-client-qualified\nphase: persistent-restart-fresh-client-qualified\nrunning 1 test\ntest postgres_matrix_restart_probe ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.20s\n'
        module.qualify_restart_probe(restart)
        marker='phase: persistent-catalog-restored-query-qualified\n'
        for output in (restart.replace(marker,''),restart+marker):
            with self.assertRaises(ValueError):module.qualify_restart_probe(output)
    def test_missing_publication_qualification_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD.replace('phase: atomic-publication-qualification-complete\n',''))
    def test_missing_snapshot_qualification_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD.replace('phase: bounded-snapshot-qualification-complete\n',''))
    def test_missing_retirement_qualification_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD.replace('phase: exact-version-retirement-qualification-complete\n',''))
    def test_missing_notification_qualification_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD.replace('phase: notification-fencing-qualification-complete\n',''))
    def test_missing_administrative_migration_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD.replace('phase: administrative-migration-qualification-complete\n',''))
    def test_zero_tests_cannot_close_gate(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output('running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s')
    def test_wrong_name_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD.replace('postgres_lease_authority_and_cancellation','other'))
    def test_ignored_test_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD.replace(' ... ok',' ... ignored'))
    def test_duplicate_test_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD+GOOD)
    def test_filtering_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD.replace('3 filtered out','1 filtered out'))
    def test_failure_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD.replace('1 passed; 0 failed','0 passed; 1 failed'))
    def test_oversized_output_rejected(self):
        with self.assertRaises(ValueError):
            module.qualify_test_output(GOOD+'x'*65537)
    def test_exhausted_work_budget_preserves_owned_cleanup_commands(self):
        self.assertEqual(module.next_command(61),62)
        with self.assertRaises(RuntimeError):
            module.next_command(62)
        self.assertEqual(module.next_command(62,cleanup=True),63)
        self.assertEqual(module.next_command(63,cleanup=True),64)
        with self.assertRaises(RuntimeError):
            module.next_command(64,cleanup=True)
    def test_minimum_postgres_version(self):
        self.assertEqual(module.qualify_server_version('170005'),170005)
        self.assertEqual(module.qualify_server_version('180000'),180000)
        for value in ('160009','17.5','0170000','170005\n','-17000','99999'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.qualify_server_version(value)
class ServerOutputGuards(unittest.TestCase):
    def test_live_shared_http_output_required(self):
        markers = ['phase: actual-shared-feed-live-http-tls-provider-durable-audit-qualified',
                   'phase: actual-owner-native-provider-http-wal-floor-deadline-expiry-replay-qualified',
                   'phase: actual-native-http-scoped-publication-legacy-unknown-original-request-resume-qualified',
               'phase: actual-native-TLS-shared-scoped-read-paired-before-limit-history-integrity-qualified',
                   'phase: actual-native-shared-scoped-http-TLS-paired-before-limit-unknown-history-durable-audit-qualified',
               'phase: read-only-original-enrollment-bootstrap-no-owner-or-mutation-qualified',
               'phase: fully-reconciled-native-WAL-restart-future-only-admission-qualified']
        tests = ['test finding_api::shared_http_tests::authorized_shared_feed_http_provider_audit ... ok',
                 'test native_owner_provider_http_wal_admission ... ok',
                 'test finding_api::shared_scoped_http_tests::authorized_shared_scoped_http_provider_audit ... ok']
        summary='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 200 filtered out;'
        good='\n'.join([*markers,*tests,summary,summary,summary])
        module.qualify_shared_http_output(good)
        bad=[good.replace(summary,'',1),good+'\n'+summary,
             good.replace('ok. 1 passed','FAILED. 1 passed',1), 'x'*65537]
        for marker in [*markers,*tests]:
            bad.extend([good.replace(marker,''),good+'\n'+marker])
        for output in bad:
            with self.subTest(output=output), self.assertRaises(ValueError):
                module.qualify_shared_http_output(output)

    def test_complete_server_output_required(self):
        marker='phase: actual-server-shared-publication-replay-query-and-orphan-fencing-qualified'
        startup='phase: actual-server-explicit-startup-wal-authority-qualified'
        feed='phase: actual-server-shared-findings-feed-wire-qualified'
        recovery='phase: actual-server-durable-request-recovery-before-wal-checkpoint-qualified'
        scoped='phase: actual-server-scoped-wal-original-claims-crash-and-startup-fencing-qualified'
        scoped_commit='phase: actual-server-scoped-lost-commit-original-claims-and-checkpoint-qualified'
        multi='phase: actual-server-multi-event-publisher-ledger-original-reconciliation-and-WAL-ack-qualified'
        multi_commit='phase: actual-server-multi-event-observed-COMMIT-cancellation-and-exact-reconciliation-qualified'
        multi_crash='phase: actual-server-multi-event-prepared-SIGKILL-boundaries-and-original-recovery-qualified'
        multi_draft_crash='phase: actual-server-multi-event-preupload-draft-SIGKILL-and-original-recovery-qualified'
        window_recovery='phase: actual-server-shared-WINDOW-fenced-state-canonical-Parquet-and-replay-pins-qualified'
        pin_transfer='phase: actual-server-replay-pin-same-version-transfer-confirmed-state-and-last-protection-qualified'
        window_history='phase: actual-server-shared-WINDOW-history-atomic-quota-outcome-expiry-pending-replay-and-retired-resurrection-qualified'
        window_history_read='phase: actual-server-shared-WINDOW-history-read-scope-cursor-expiry-corruption-and-cancellation-qualified'
        obsolete_pin='phase: actual-server-WINDOW-indeterminate-history-and-complete-obsolete-pin-accounting-qualified'
        window_profile='phase: actual-server-WINDOW-profile-explicit-bootstrap-grants-quotas-and-protected-delayed-anchor-qualified'
        multi_crashed=[f'recovery-process: multi-{mode} owned child SIGKILL observed and reaped' for mode in ('draft','before-commit','after-commit','after-ack')]
        crashed=[f'recovery-process: {mode} owned child SIGKILL observed and reaped' for mode in ('draft','before-commit','after-commit','after-ack')]
        scoped_crashed=[f'recovery-process: scoped-{mode} owned child SIGKILL observed and reaped' for mode in ('draft','before-commit','after-commit','after-ack')]
        summary='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;'
        required=[marker,startup,recovery,feed,scoped,scoped_commit,multi,multi_commit,multi_crash,multi_draft_crash,window_recovery,pin_transfer,window_history,window_history_read,obsolete_pin,window_profile,*multi_crashed,*crashed,*scoped_crashed]
        good='\n'.join([*required,summary])
        module.qualify_server_output(good)
        for output in [summary, *[good.replace(value+'\n','') for value in required], *[good+'\n'+value for value in required], good.replace('ok.', 'FAILED.')]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                module.qualify_server_output(output)


if __name__=='__main__':
    unittest.main()

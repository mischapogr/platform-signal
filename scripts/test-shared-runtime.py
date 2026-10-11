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
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 3.83s
"""
class Guards(unittest.TestCase):
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
            for codes,status,count in [([2,1,0],0,3),([2],1,60),([3],3,1)]:
                with self.subTest(codes=codes):
                    trace.unlink(missing_ok=True)
                    result=subprocess.run(['sh','-c',module.READY_SCRIPT],
                        env=dict(os.environ,PATH=str(directory)+os.pathsep+os.environ['PATH'],
                                 READY_TRACE=str(trace),READY_CODES=json.dumps(codes)),
                        capture_output=True,text=True,timeout=3)
                    self.assertEqual(result.returncode,status,result.stderr)
                    calls=[json.loads(line) for line in trace.read_text().splitlines()]
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
        good="phase: current-finding-scope-original-host-authority-after-restart-qualified\nphase: shared-finding-scope-persistent-restart-original-authority-qualified\nphase: persistent-restored-global-feed-qualified\nphase: persistent-catalog-restored-query-qualified\nphase: persistent-catalog-restart-fresh-client-qualified\nphase: persistent-restart-fresh-client-qualified\nrunning 1 test\ntest postgres_matrix_restart_probe ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.20s\n"
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
        for marker in ('phase: globally-authorized-original-feed-qualified\n', 'phase: globally-authorized-restored-feed-qualified\n', 'phase: shared-finding-scope-stopped-schema-and-immutable-prefix-qualified\n'):
            for output in (GOOD.replace(marker, ''), GOOD + marker):
                with self.assertRaises(ValueError):module.qualify_test_output(output)
        good='phase: current-finding-scope-original-host-authority-after-restart-qualified\nphase: shared-finding-scope-persistent-restart-original-authority-qualified\nphase: persistent-restored-global-feed-qualified\nphase: persistent-catalog-restored-query-qualified\nphase: persistent-catalog-restart-fresh-client-qualified\nphase: persistent-restart-fresh-client-qualified\nrunning 1 test\ntest postgres_matrix_restart_probe ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.20s\n'
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
        good='phase: current-finding-scope-original-host-authority-after-restart-qualified\nphase: shared-finding-scope-persistent-restart-original-authority-qualified\nphase: persistent-restored-global-feed-qualified\nphase: persistent-catalog-restored-query-qualified\nphase: persistent-catalog-restart-fresh-client-qualified\nphase: persistent-restart-fresh-client-qualified\nrunning 1 test\ntest postgres_matrix_restart_probe ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.20s\n'
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
        output="phase: persistent-restart-fresh-client-qualified\nrunning 1 test\ntest postgres_matrix_restart_probe ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.20s\n"
        with self.assertRaises(ValueError):module.qualify_restart_probe(output)
    def test_missing_or_duplicated_query_composition_rejected(self):
        marker='phase: shared-catalog-actual-parquet-query-composition-complete\n'
        for output in (GOOD.replace(marker,''),GOOD+marker):
            with self.assertRaises(ValueError):module.qualify_test_output(output)
    def test_catalog_restore_and_restart_cannot_be_missing_or_duplicated(self):
        marker='phase: coordinated-catalog-restore-and-actual-query-qualified\n'
        for output in (GOOD.replace(marker,''),GOOD+marker):
            with self.assertRaises(ValueError):module.qualify_test_output(output)
        restart='phase: current-finding-scope-original-host-authority-after-restart-qualified\nphase: shared-finding-scope-persistent-restart-original-authority-qualified\nphase: persistent-restored-global-feed-qualified\nphase: persistent-catalog-restored-query-qualified\nphase: persistent-catalog-restart-fresh-client-qualified\nphase: persistent-restart-fresh-client-qualified\nrunning 1 test\ntest postgres_matrix_restart_probe ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.20s\n'
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
            module.qualify_test_output(GOOD.replace('2 filtered out','1 filtered out'))
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
                   'phase: actual-native-shared-scoped-http-TLS-paired-before-limit-unknown-history-durable-audit-qualified']
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
        crashed=[f'recovery-process: {mode} owned child SIGKILL observed and reaped' for mode in ('draft','before-commit','after-commit','after-ack')]
        scoped_crashed=[f'recovery-process: scoped-{mode} owned child SIGKILL observed and reaped' for mode in ('draft','before-commit','after-commit','after-ack')]
        summary='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;'
        required=[marker,startup,recovery,feed,scoped,scoped_commit,*crashed,*scoped_crashed]
        good='\n'.join([*required,summary])
        module.qualify_server_output(good)
        for output in [summary, *[good.replace(value+'\n','') for value in required], *[good+'\n'+value for value in required], good.replace('ok.', 'FAILED.')]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                module.qualify_server_output(output)


if __name__=='__main__':
    unittest.main()

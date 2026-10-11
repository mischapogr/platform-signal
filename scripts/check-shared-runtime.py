#!/usr/bin/env python3
"""Qualify explicit administration and shared-control primitives against owned PostgreSQL, not HA readiness."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shutil
from pathlib import Path
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SECONDS = 240
STANDARD_SECONDS = 180


def elapsed_within_fixture_budget(elapsed, *, combined_standard=False):
    if type(combined_standard) is not bool:return False
    budget=FIXTURE_SECONDS+(STANDARD_SECONDS if combined_standard else 0)
    return type(elapsed) in (int, float) and 0 <= elapsed <= budget

def capture_standard_binary(source,destination):
    # Debug DataFusion executables include substantial DWARF; bound disk bytes
    # without requiring the release profile or allocating the image in memory.
    if source.is_symlink() or not source.is_file() or not 0<source.stat().st_size<=2*1024*1024*1024:
        raise ValueError('prebuilt Standard executable missing or outside byte bounds')
    if destination.exists() or destination.is_symlink():
        raise ValueError('owned Standard executable snapshot must be absent')
    shutil.copyfile(source,destination)
    destination.chmod(0o700)
    with destination.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()

def qualify_standard_report(report, binary_sha256):
    if not isinstance(report,dict):
        raise ValueError('actual Standard executable report shape')
    expected=['actual_Standard_native_TLS_ingest_versioned_S3_query_scoped_findings_global_feed_graceful_shutdown',
              'actual_Standard_stopped_original_WAL_explicit_holds_exact_retirement_stale_fence',
              'actual_Standard_stopped_restart_original_enrollment_and_current_query',
              'actual_Standard_SIGKILL_saved_original_request_manifest_once_checkpoint3',
              'actual_Standard_unprepared_native_WAL_restart_held_original_row_checkpoint3']
    if (report.get('schema_version')!=1 or report.get('status')!='passed_simulated'
            or report.get('original_publication_crash_recovery_qualified') is not True
            or report.get('unprepared_native_wal_hold_qualified') is not True
            or report.get('child_capacity')!=3 or report.get('log_capacity')!=24
            or report.get('producer_credentials_qualified') is not True
            or report.get('empty_catalog_qualified') is not True
            or report.get('selected_coverage_startup_and_restart_qualified') is not True
            or report.get('missing_coverage_failure_qualified') is not True
            or type(report.get('missing_coverage_failure_seconds')) not in (int,float)
            or not 0 <= report['missing_coverage_failure_seconds'] < 5
            or report.get('invalid_cache_failure_qualified') is not True
            or type(report.get('invalid_cache_failure_seconds')) not in (int,float)
            or not 0 <= report['invalid_cache_failure_seconds'] < 5
            or report.get('late_startup_failure_qualified') is not True
            or type(report.get('late_startup_failure_seconds')) not in (int,float)
            or not 0 <= report['late_startup_failure_seconds'] < 5
            or report.get('startup_interruption_qualified') is not True
            or type(report.get('startup_interruption_seconds')) not in (int,float)
            or not 0 <= report['startup_interruption_seconds'] < 3
            or report.get('startup_denials')!=['owner-capable-producer','direct-reader-as-producer']
            or report.get('binary_sha256')!=binary_sha256
            or type(report.get('provider_calls')) is not int or not 1<=report['provider_calls']<=64):
        raise ValueError('actual Standard executable report bindings incomplete')
    scenarios=report.get('scenarios')
    if not isinstance(scenarios,list) or len(scenarios)!=5 or any(not isinstance(row,dict) for row in scenarios):
        raise ValueError('actual Standard executable scenarios incomplete')
    if [row.get('name') for row in scenarios]!=expected or any(row.get('status')!='passed_simulated' for row in scenarios):
        raise ValueError('actual Standard executable scenarios missing or duplicated')
    identifiers=scenarios[0].get('event_ids')
    if not isinstance(identifiers,list) or len(identifiers)!=2:
        raise ValueError('actual Standard executable event identities')
    for value in identifiers:
        if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value) or uuid.UUID(value).int==0:
            raise ValueError('actual Standard executable event identities')
    if len(set(identifiers))!=2:
        raise ValueError('actual Standard executable duplicate event identities')
    crash=scenarios[3]
    for field,report_field in [('event_id','original_crash_event_id'),('request_id','original_crash_request_id')]:
        value=crash.get(field)
        if (not isinstance(value,str) or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value)
                or uuid.UUID(value).int==0 or report.get(report_field)!=value):
            raise ValueError('actual Standard original crash operation binding')
    if crash['event_id'] in identifiers:
        raise ValueError('actual Standard crash must admit a new distinct event')
    pending=scenarios[4].get('event_id')
    if (not isinstance(pending,str) or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',pending)
            or uuid.UUID(pending).int==0 or report.get('pending_native_event_id')!=pending
            or pending in identifiers+[crash['event_id']]):
        raise ValueError('actual Standard held native event binding')


def qualify_standard_audit_report(report,binary_sha256):
    expected=['actual_Standard_activation_receipts_before_ready_independent_receiver_survives_stop',
              'actual_Standard_required_audit_outage_holds_with_original_pending_receipt',
              'actual_Standard_original_audit_replay_fresh_activations_existing_receiver_empty_WAL']
    if not isinstance(report,dict) or report.get('schema_version')!=1 or report.get('status')!='passed_simulated':
        raise ValueError('Standard audit report shape')
    scenarios=report.get('scenarios')
    if (not isinstance(scenarios,list) or len(scenarios)!=3 or any(not isinstance(r,dict) for r in scenarios)
            or [r.get('name') for r in scenarios]!=expected or any(r.get('status')!='passed_simulated' for r in scenarios)
            or report.get('binary_sha256')!=binary_sha256 or report.get('child_capacity')!=3 or report.get('log_capacity')!=24
            or any(report.get(k) is not True for k in ('independent_receiver_qualified','exact_pending_replay_qualified','empty_WAL_qualified'))
            or type(report.get('required_audit_failure_seconds')) not in (int,float) or not 0<=report['required_audit_failure_seconds']<7
            or type(report.get('provider_calls')) is not int or not 1<=report['provider_calls']<=64
            or not isinstance(report.get('original_pending_sha256'),str) or not re.fullmatch('[0-9a-f]{64}',report['original_pending_sha256'])):
        raise ValueError('Standard audit report qualification incomplete')
    ids=report.get('audit_record_ids')
    if not isinstance(ids,list) or len(ids)!=5 or any(not isinstance(i,str) for i in ids) or len(set(ids))!=5:
        raise ValueError('Standard audit original record identities')
    for value in ids+[report.get('audit_producer_id')]:
        if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value) or not uuid.UUID(value).int:
            raise ValueError('Standard audit original identity binding')


def qualify_standard_private_report(report,binary_sha256):
    names=['actual_Standard_native_feed_private_atomic_outbox_exact_replay_three_attempt_notifications',
           'actual_Standard_original_feed_cursor_private_restart_no_historical_redelivery']
    if not isinstance(report,dict):raise ValueError('Standard private report shape')
    scenarios=report.get('scenarios')
    if (report.get('schema_version')!=1 or report.get('status')!='passed_simulated'
            or report.get('binary_sha256')!=binary_sha256 or report.get('child_capacity')!=3 or report.get('log_capacity')!=24
            or report.get('private_original_cursor_restart_qualified') is not True
            or report.get('populated_scope_restore_stage_qualified') is not True
            or type(report.get('notification_calls')) is not int or report['notification_calls']!=6
            or type(report.get('notification_deliveries')) is not int or report['notification_deliveries']!=2
            or type(report.get('provider_calls')) is not int or not 1<=report['provider_calls']<=64
            or not isinstance(report.get('raw_feed_sha256'),str) or not re.fullmatch('[0-9a-f]{64}',report['raw_feed_sha256'])
            or not isinstance(scenarios,list) or len(scenarios)!=2 or any(not isinstance(r,dict) for r in scenarios)
            or [r.get('name') for r in scenarios]!=names or any(r.get('status')!='passed_simulated' for r in scenarios)):
        raise ValueError('Standard private qualification incomplete')
    for field in ('private_binary_sha256','notification_witness_sha256'):
        if not isinstance(report.get(field),str) or not re.fullmatch('[0-9a-f]{64}',report[field]):raise ValueError('Standard private retained witness binding')
    ids=report.get('event_ids')
    if not isinstance(ids,list) or len(ids)!=2 or ids!=scenarios[0].get('event_ids') or any(not isinstance(i,str) for i in ids):
        raise ValueError('Standard private event identity binding')
    for value in ids:
        if not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value) or not uuid.UUID(value).int:
            raise ValueError('Standard private event identity')
    if len(set(ids))!=2:raise ValueError('Standard private distinct events')

def qualify_standard_restore_report(report,binary_sha256):
    if not isinstance(report,dict):raise ValueError('Standard restore report shape')
    scenarios=report.get('scenarios')
    name='actual_Standard_fresh_destination_generation_original_cursor_restart_and_new_native_publication'
    if not isinstance(scenarios,list) or len(scenarios)!=2 or any(not isinstance(row,dict) for row in scenarios) or scenarios[1].get('name')!=name:
        raise ValueError('Standard restore scenarios')
    adapted=dict(report);adapted['scenarios']=[dict(row) for row in scenarios]
    adapted['scenarios'][1]['name']='actual_Standard_original_feed_cursor_private_restart_no_historical_redelivery'
    qualify_standard_private_report(adapted,binary_sha256)
    receipt=report.get('restore_receipt')
    if (report.get('scoped_restore_generation_qualified') is not True or report.get('restored_native_publication_qualified') is not True
            or report.get('restored_retirement_qualified') is not True
            or report.get('old_generation_Main_fenced') is not True or report.get('original_source_checkpoint_unchanged') is not True
            or not isinstance(receipt,dict) or receipt.get('schema_version')!=1
            or any(receipt.get(key) is not True for key in ('ready','scope_original_bytes_preserved','consumer_current_reconciled','scoped_ddl_error_rollback','scoped_ddl_cancel_rollback','scoped_lost_commit_resolved','scoped_consumer_resume_refused'))):
        raise ValueError('Standard restore completion witnesses')
    for key in ('generation','old_generation'):
        value=receipt.get(key)
        if not isinstance(value,str) or not uuid.UUID(value).int:raise ValueError('Standard restore generation')
    if receipt['generation']==receipt['old_generation']:raise ValueError('Standard restore fresh generation')
    inventory=receipt.get('inventory')
    if (not isinstance(inventory,dict) or inventory.get('old_generation')!=receipt['old_generation']
            or inventory.get('feed_position')!=2 or inventory.get('revision')!=4
            or not isinstance(inventory.get('objects'),list) or not inventory['objects']
            or not isinstance(inventory.get('consumers'),list) or len(inventory['consumers'])!=1
            or not isinstance(inventory['consumers'][0],dict) or inventory['consumers'][0].get('position')!=2):
        raise ValueError('Standard restore original inventory binding')
    event=report.get('restored_event_id')
    if not isinstance(event,str) or not uuid.UUID(event).int or event in report['event_ids'] or scenarios[1].get('event_id')!=event:
        raise ValueError('Standard restored new native event')

def private_source_hashes(root):
    root=root.resolve(strict=True)
    if root.is_relative_to(ROOT) or not (root/'tests/standard_main.rs').is_file():raise ValueError('external private fixture required')
    paths=[root/'Cargo.toml',root/'Cargo.lock']
    for tree in ('src','tests'):
        for path in (root/tree).rglob('*'):
            if path.is_symlink():raise ValueError('private fixture source symlink')
            if path.is_file():paths.append(path)
    if len(paths)>256:raise ValueError('private fixture source capacity')
    result={}
    for path in sorted(paths):
        if path.stat().st_size>2*1024*1024:raise ValueError('private fixture source byte capacity')
        result[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
    return result



# One charged Docker command; each connection probe and the retry count are finite.
# This owned-container loop cannot consume the four cleanup command slots.
READY_SCRIPT = '''attempt=0
attempt_limit=${1:-60}
case "$attempt_limit" in 60|120) ;; *) exit 3 ;; esac
while [ "$attempt" -lt "$attempt_limit" ]; do
    pg_isready -q -t 1 -h 127.0.0.1 -U postgres
    result=$?
    case "$result" in
        0) exit 0 ;;
        1|2) ;;
        *) exit "$result" ;;
    esac
    attempt=$((attempt+1))
    if [ "$attempt" -lt "$attempt_limit" ]; then sleep .5; fi
done
exit 1
'''

def qualify_test_output(output):
    if len(output.encode('utf-8'))>65536:
        raise ValueError('fixture test output byte capacity')
    lines=output.splitlines()
    for marker in ('phase: globally-authorized-original-feed-qualified','phase: globally-authorized-restored-feed-qualified','phase: shared-finding-scope-stopped-schema-and-immutable-prefix-qualified','phase: current-finding-scope-activation-enrollment-counters-and-authority-qualified','phase: atomic-original-scoped-publication-facts-counters-and-startup-fencing-qualified'):
        if lines.count(marker)!=1:
            raise ValueError('current globally authorized original/restored feed qualification missing')
    if lines.count('phase: dynamic-catalog-and-stopped-profile-qualification-complete')!=1:
        raise ValueError('dynamic catalog and stopped profile qualification missing')
    if lines.count('phase: shared-catalog-actual-parquet-query-composition-complete')!=1:
        raise ValueError('shared catalog/Parquet/query composition missing')
    if lines.count('phase: coordinated-catalog-restore-and-actual-query-qualified')!=1:
        raise ValueError('coordinated catalog restore/query qualification missing')
    if lines.count('running 1 test')!=1 or lines.count('test postgres_lease_authority_and_cancellation ... ok')!=1:
        raise ValueError('named PostgreSQL fixture test did not execute exactly once')
    if lines.count('phase: coordinated-stopped-restore-qualification-complete')!=1:
        raise ValueError('coordinated restore qualification did not complete exactly once')
    if lines.count('phase: administrative-migration-qualification-complete')!=1:
        raise ValueError('administrative migration qualification did not complete exactly once')
    if lines.count('phase: atomic-publication-qualification-complete')!=1:
        raise ValueError('atomic publication qualification did not complete exactly once')
    if lines.count('phase: bounded-snapshot-qualification-complete')!=1:
        raise ValueError('bounded snapshot qualification did not complete exactly once')
    if lines.count('phase: notification-fencing-qualification-complete')!=1:
        raise ValueError('notification fencing qualification did not complete exactly once')
    if lines.count('phase: exact-version-retirement-qualification-complete')!=1:
        raise ValueError('exact-version retirement qualification did not complete exactly once')
    results=[line for line in lines if line.startswith('test result:')]
    if len(results)!=1 or re.fullmatch(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in [0-9]+(?:\.[0-9]+)?s',results[0]) is None:
        raise ValueError('PostgreSQL fixture test counts')


def qualify_matrix_output(output):
    qualify_test_output(output)
    if output.splitlines().count('phase: crash-marker-atomic-publication-qualified')!=1:
        raise ValueError('atomic crash-worker marker qualification missing or duplicated')
    frozen=json.loads((ROOT/'schemas/shared-control/v1.json').read_text())['failure_matrix']
    expected={item['id'] for item in frozen}
    cases=[line for line in output.splitlines() if line.startswith('matrix-case:')]
    wanted={f'matrix-case:{case} passed' for case in expected}
    if len(expected)!=18 or len(cases)!=18 or set(cases)!=wanted:
        raise ValueError('all eighteen unique frozen matrix cases must complete')
    if output.splitlines().count('phase: abrupt-process-crash-qualification-complete')!=1:
        raise ValueError('actual abrupt process crash qualification missing or duplicated')
    return frozen


def qualify_restart_witness(before,after):
    expected={'postgres','signal_restore_destination','signal_catalog_profile','signal_catalog_restore_source','signal_catalog_restore_destination','signal_finding_scope_fixture'}
    if set(before)!=expected or set(after)!=expected or before!=after:
        raise ValueError('persistent metadata changed or required database absent')
    if any(not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}',value) is None for value in before.values()):
        raise ValueError('persistent metadata witness digest')


def qualify_restart_probe(output):
    if len(output.encode('utf-8'))>65536:
        raise ValueError('restart probe output byte capacity')
    lines=output.splitlines()
    if lines.count('phase: persistent-restored-global-feed-qualified')!=1 or lines.count('phase: shared-finding-scope-persistent-restart-original-authority-qualified')!=1:
        raise ValueError('restored global feed persistent restart qualification missing')
    if lines.count('phase: current-finding-scope-original-host-authority-after-restart-qualified')!=1:
        raise ValueError('current scope host authority persistent restart qualification missing')
    if lines.count('phase: persistent-catalog-restart-fresh-client-qualified')!=1:
        raise ValueError('dynamic catalog persistent restart qualification missing')
    if lines.count('phase: persistent-catalog-restored-query-qualified')!=1:
        raise ValueError('restored catalog persistent query qualification missing')
    if lines.count('running 1 test')!=1 or lines.count('test postgres_matrix_restart_probe ... ok')!=1 or lines.count('phase: persistent-restart-fresh-client-qualified')!=1:
        raise ValueError('fresh-client restart probe must execute exactly once')
    results=[line for line in lines if line.startswith('test result:')]
    if len(results)!=1 or re.fullmatch(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in [0-9]+(?:\.[0-9]+)?s',results[0]) is None:
        raise ValueError('fresh-client restart probe counts')


def qualify_server_version(value):
    if re.fullmatch('[0-9]{6}',value) is None or int(value)<170000:
        raise ValueError('PostgreSQL17 or later fixture required')
    return int(value)


def next_command(count,cleanup=False):
    # Reserve the final two commands for owned identity verification/removal.
    if count >= (64 if cleanup else 62):
        raise RuntimeError('shared fixture command capacity')
    return count+1


def qualify_server_output(output):
    marker='phase: actual-server-shared-publication-replay-query-and-orphan-fencing-qualified'
    startup='phase: actual-server-explicit-startup-wal-authority-qualified'
    feed='phase: actual-server-shared-findings-feed-wire-qualified'
    recovery='phase: actual-server-durable-request-recovery-before-wal-checkpoint-qualified'
    scoped='phase: actual-server-scoped-wal-original-claims-crash-and-startup-fencing-qualified'
    scoped_commit='phase: actual-server-scoped-lost-commit-original-claims-and-checkpoint-qualified'
    crashed=[f'recovery-process: {mode} owned child SIGKILL observed and reaped' for mode in ('draft','before-commit','after-commit','after-ack')]
    scoped_crashed=[f'recovery-process: scoped-{mode} owned child SIGKILL observed and reaped' for mode in ('draft','before-commit','after-commit','after-ack')]
    if any(output.splitlines().count(value)!=1 for value in [marker,startup,recovery,feed,scoped,scoped_commit,*crashed,*scoped_crashed]) or not re.search(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;',output):
        raise ValueError('server shared publication qualification missing or ambiguous')


def qualify_shared_http_output(output):
    markers = ('phase: actual-shared-feed-live-http-tls-provider-durable-audit-qualified',
               'phase: actual-owner-native-provider-http-wal-floor-deadline-expiry-replay-qualified',
               'phase: actual-native-http-scoped-publication-legacy-unknown-original-request-resume-qualified',
               'phase: actual-native-TLS-shared-scoped-read-paired-before-limit-history-integrity-qualified',
               'phase: actual-native-shared-scoped-http-TLS-paired-before-limit-unknown-history-durable-audit-qualified',
               'phase: read-only-original-enrollment-bootstrap-no-owner-or-mutation-qualified',
               'phase: fully-reconciled-native-WAL-restart-future-only-admission-qualified')
    tests = ('test finding_api::shared_http_tests::authorized_shared_feed_http_provider_audit ... ok',
             'test native_owner_provider_http_wal_admission ... ok',
             'test finding_api::shared_scoped_http_tests::authorized_shared_scoped_http_provider_audit ... ok')
    lines = output.splitlines()
    summaries = [line for line in lines if line.startswith('test result:')]
    if (len(output.encode('utf-8')) > 65536
            or any(lines.count(marker) != 1 for marker in (*markers, *tests))
            or len(summaries) != 3
            or any(not re.match(r'test result: ok\. 1 passed; 0 failed; 0 ignored;', s) for s in summaries)):
        raise ValueError('live shared HTTP/provider/audit and owner/WAL qualification missing or ambiguous')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', default='postgres:17.5-alpine')
    parser.add_argument('--matrix', action='store_true', help='owned persistent volume and abrupt database restart qualification')
    parser.add_argument('--server', action='store_true', help='actual monolithic server publication/rules/query coordinator qualification')
    parser.add_argument('--standard', action='store_true', help='actual Standard executable with owned TLS and persistent S3 protocol fixture')
    parser.add_argument('--standard-only', action='store_true', help='focused Standard process calibration; excludes library and crash matrices')
    parser.add_argument('--standard-kubernetes-image', help='qualify this local image in an owned Standard kind cluster; requires --standard-only')
    parser.add_argument('--standard-audit-only',action='store_true',help='focused actual Standard independent audit receiver lifecycle; excludes pipeline/library/crash matrices')
    parser.add_argument('--standard-private-only',action='store_true',help='actual Standard feed/private outbox and notification qualification; excludes restore/full matrices')
    parser.add_argument('--standard-restore-only',action='store_true',help='fresh scoped destination and actual restored Standard/private progress; excludes full matrices')
    parser.add_argument('--private-checkout',type=Path,default=ROOT.parent/'platform-signal-private')
    args = parser.parse_args()
    if args.standard_kubernetes_image and not args.standard_only:
        parser.error('--standard-kubernetes-image requires --standard-only')
    if args.standard_restore_only:
        if args.matrix or args.server or args.standard_only or args.standard_audit_only or args.standard_private_only:parser.error('--standard-restore-only excludes other focused/full matrices')
        args.standard=True
    if args.standard_private_only:
        if args.matrix or args.server or args.standard_only or args.standard_audit_only:parser.error('--standard-private-only excludes other focused/full matrices')
        args.standard=True
    if args.standard_audit_only:
        if args.matrix or args.server or args.standard_only:parser.error('--standard-audit-only excludes other focused/full matrices')
        args.standard=True
    if args.standard_only:
        if args.matrix or args.server:
            parser.error('--standard-only cannot claim the library/server crash matrices')
        args.standard=True
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('shared_runtime_command', ROOT/'scripts/check-native-qualification.py')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    began = time.monotonic()
    # Expanded control/restore and server crash matrices need separate harness
    # headroom. This never extends any production operation context or SQL timeout.
    focused=args.standard_only or args.standard_audit_only or args.standard_private_only or args.standard_restore_only
    combined_standard=args.standard and not focused
    fixture_seconds=FIXTURE_SECONDS+(STANDARD_SECONDS if combined_standard else 0)
    if args.standard_kubernetes_image:
        fixture_seconds = 600
    deadline = began+fixture_seconds
    name = 'signal-shared-runtime-'+uuid.uuid4().hex
    password = 'synthetic-control-'+uuid.uuid4().hex
    image = None
    created = False
    volume_created = False
    volume_name = name+'-pgdata'
    count = 0
    report = {'status':'failed','scope':'owned PostgreSQL administration/lease/publication/receipt/replay/snapshot/retirement/retention/notification/coordinated-stopped-restore/permission/cancellation primitives only; shared runtime remains unfinished',
              'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'container_name':name, 'checks':[], 'cleanup_errors':[], 'fixture_seconds':fixture_seconds}
    def run(argv, seconds=5, env=None, cleanup=False):
        nonlocal count
        if not cleanup and volume_created and count>=60:
            raise RuntimeError('persistent fixture cleanup command reserve')
        count = next_command(count,cleanup)
        remaining = deadline-time.monotonic()-(0 if cleanup else 10)
        if remaining<=0:
            raise RuntimeError('shared fixture command/deadline capacity')
        with (out/f'command-{count:02}.log').open('xb') as log:
            command = argv if env is None else ['env','-i',*[key+'='+value for key,value in sorted(env.items())],*argv]
            return gate.run_bounded(command, log, timeout=min(seconds,remaining), grace=1).strip()
    def sql(text):
        return run(['docker','exec',name,'psql','-X','-U','postgres','-d','postgres','-At','-v','ON_ERROR_STOP=1','-c',text])
    primary = None
    try:
        if args.standard:
            # Default-feature integration Cargo commands below replace the
            # normal target/debug binary. Preserve the prebuilt Standard image
            # before running them, without charging compilation to runtime gates.
            standard_binary=out/'standard-server'
            report['standard_binary_sha256']=capture_standard_binary(ROOT/'target/debug/signal-server',standard_binary)
        inspected = json.loads(run(['docker','image','inspect',args.image]))[0]
        image = inspected['Id']
        if inspected['Os']!='linux' or inspected['Architecture'] not in ('amd64','arm64'):
            raise RuntimeError('fixture image platform')
        report['image']=image
        report['architecture']=inspected['Architecture']
        if args.matrix:
            run(['docker','volume','create','--label','signal.shared.runtime='+name,volume_name])
            volume_created=True
            mount=['--mount','type=volume,source='+volume_name+',target=/var/lib/postgresql/data']
            report['persistent_volume']=volume_name
        else:
            mount=['--tmpfs','/var/lib/postgresql/data:rw,size=96m']
        container = run(['docker','run','--detach','--name',name,'--memory','256m','--cpus','1','--pids-limit','64',
                         '--label','signal.shared.runtime='+name,'--publish','127.0.0.1::5432',
                         '--env','POSTGRES_PASSWORD='+password,'--env','PGDATA=/var/lib/postgresql/data/pgdata',
                         *mount,image],10)
        created=True
        report['container']=container
        run(['docker','exec',name,'sh','-c',READY_SCRIPT],35)
        metadata=json.loads(run(['docker','inspect',name]))[0]
        bindings=metadata['NetworkSettings']['Ports']['5432/tcp']
        if len(bindings)!=1 or bindings[0]['HostIp']!='127.0.0.1':
            raise RuntimeError('fixture loopback publication')
        port=int(bindings[0]['HostPort'])
        if not 1<=port<=65535:
            raise RuntimeError('fixture port range')
        report['server_version_num']=qualify_server_version(sql("SELECT current_setting('server_version_num')"))
        report['checks'].append('owned_cached_postgres17_or_later_loopback_ready')
        sql("CREATE ROLE signal_control_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; GRANT CREATE ON DATABASE postgres TO signal_control_owner;")
        base=(ROOT/'schemas/shared-control/001.sql').read_bytes()
        routines=(ROOT/'schemas/shared-control/002-functions.sql').read_bytes()
        if len(base)>65536 or len(routines)>262144:
            raise RuntimeError('migration byte capacity')
        report['schema_sha256']=hashlib.sha256(base).hexdigest()
        report['legacy_routines_sha256']=hashlib.sha256(routines).hexdigest()
        report['routines_sha256']=hashlib.sha256((ROOT/'schemas/shared-control/003-administration.sql').read_bytes()).hexdigest()
        report['restored_routines_sha256']=hashlib.sha256((ROOT/'schemas/shared-control/004-restore.sql').read_bytes()).hexdigest()
        sql('SET ROLE signal_control_owner; '+base.decode())
        sql('SET ROLE signal_control_owner; '+routines.decode())
        catalog=sql('SET search_path=pg_catalog,signal_control,pg_temp; '+(ROOT/'schemas/shared-control/catalog-query.sql').read_text()).splitlines()[-1]
        if not re.fullmatch(r'[0-9a-f]{64}',catalog):
            raise RuntimeError('legacy catalog fingerprint')
        (out/'legacy-catalog.json').write_text(json.dumps({'catalog_sha256':catalog,'schema_sha256':report['schema_sha256'],'routines_sha256':report['legacy_routines_sha256']},indent=2)+'\n')
        role_sql="""
CREATE ROLE signal_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE IN ROLE signal_control_owner PASSWORD '%s';
CREATE ROLE signal_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '%s';
CREATE ROLE signal_denied LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '%s';
GRANT USAGE ON SCHEMA signal_control TO signal_runtime,signal_denied;
GRANT EXECUTE ON FUNCTION signal_control.acquire(jsonb,uuid,integer,bytea,bytea), signal_control.renew(jsonb,integer,bytea,bytea), signal_control.record_receipt(jsonb,bytea,bytea,bytea), signal_control.publish(jsonb,bytea,boolean,bytea,bytea), signal_control.read_snapshot(jsonb,uuid,uuid[],integer,bytea,bytea), signal_control.object_control(jsonb,bytea,bytea,bytea), signal_control.notification(jsonb,bytea,bytea,bytea) TO signal_runtime,signal_denied;
ALTER ROLE signal_runtime SET statement_timeout='2s';
ALTER ROLE signal_runtime SET lock_timeout='500ms';
ALTER ROLE signal_runtime SET idle_in_transaction_session_timeout='2s';
""" % (password,password,password)
        sql(role_sql)
        sql("INSERT INTO signal_control.store(singleton,store_id,generation,revision,ready,feed_digest,schema_sha256,routines_sha256,max_rows,max_bytes) VALUES (true,'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',1,false,sha256(convert_to('SIGNAL-FINDINGS-CURSOR-V1','UTF8')||decode(repeat('0',31)||'1','hex')),decode('%s','hex'),decode('%s','hex'),65536,67108864);" % (report['schema_sha256'],report['legacy_routines_sha256']))
        sql("INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES ('00000000-0000-0000-0000-000000000004','synthetic','00000000-0000-0000-0000-000000000003','pipeline'); INSERT INTO signal_control.principals(role_name,tenant,stream,partition_id) VALUES ('signal_runtime','synthetic','00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000004');")
        sql("INSERT INTO signal_control.object_backends(id,canonical_id) VALUES('00000000-0000-0000-0000-000000000020','fixture-control-object-namespace-v1'); INSERT INTO signal_control.object_scopes(partition_id,backend_id,key_prefix) VALUES('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000020','query/00000000-0000-0000-0000-000000000003/');")
        report['checks'].append('explicit_schema_owner_and_restricted_runtime_roles')
        certs=out/'certs'
        certs.mkdir(mode=0o700)
        for prefix, common in (('root','synthetic-control-ca'),('wrong','synthetic-untrusted-ca')):
            run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-noenc',
                 '-keyout',str(certs/(prefix+'.key')),'-out',str(certs/(prefix+'.pem')),'-days','1',
                 '-subj','/CN='+common,'-addext','basicConstraints=critical,CA:TRUE',
                 '-addext','keyUsage=critical,keyCertSign,cRLSign'])
            run(['openssl','x509','-in',str(certs/(prefix+'.pem')),'-outform','DER','-out',str(certs/(prefix+'.der'))])
        run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-noenc',
             '-keyout',str(certs/'leaf.key'),'-out',str(certs/'leaf.csr'),'-subj','/CN=signal-control.invalid'])
        (certs/'leaf.ext').write_text('subjectAltName=DNS:signal-control.invalid,IP:127.0.0.1\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n')
        run(['openssl','x509','-req','-in',str(certs/'leaf.csr'),'-CA',str(certs/'root.pem'),'-CAkey',str(certs/'root.key'),
             '-set_serial','2','-days','1','-extfile',str(certs/'leaf.ext'),'-out',str(certs/'leaf.pem')])
        for key in ('root.key','wrong.key','leaf.key'):
            (certs/key).chmod(0o600)
        for filename in ('leaf.key','leaf.pem'):
            content=(certs/filename).read_text()
            if len(content)>65536:
                raise RuntimeError('synthetic TLS fixture byte capacity')
            run(['docker','exec','--user','0',name,'sh','-c',
                 'set -e; umask 077; printf \"%s\" \"$1\" > \"$2\"; chown postgres:postgres \"$2\"',
                 '--',content,'/var/lib/postgresql/data/'+filename])
        sql("ALTER SYSTEM SET ssl_cert_file='/var/lib/postgresql/data/leaf.pem'")
        sql("ALTER SYSTEM SET ssl_key_file='/var/lib/postgresql/data/leaf.key'")
        sql("ALTER SYSTEM SET ssl='on'")
        sql('SELECT pg_reload_conf()')
        report['checks'].append('owned_postgres_tls_with_independent_untrusted_ca')
        config=out/'fixture.json'
        with config.open('x') as stream:
            json.dump({'port':port,'password':password,'root_der':str(certs/'root.der'),'wrong_der':str(certs/'wrong.der')},stream)
        config.chmod(0o600)
        env={key:os.environ[key] for key in ('PATH','HOME','RUSTUP_HOME','CARGO_HOME','CARGO_TARGET_DIR','LANG','LC_ALL','TMPDIR') if key in os.environ}
        env['SIGNAL_CONTROL_FIXTURE']=str(config)
        if args.standard_private_only or args.standard_restore_only:
            report['private_source_hashes']=private_source_hashes(args.private_checkout)
            env['SIGNAL_STANDARD_PRIVATE_CHECKOUT']=str(args.private_checkout.resolve(strict=True))
        report['source_hashes']={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted([ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'scripts/check-shared-runtime.py',
                               *list((ROOT/'crates/signal-control').rglob('*.rs')),ROOT/'crates/signal-control/Cargo.toml',
                               *list((ROOT/'crates/signal-storage/src').rglob('*.rs')),ROOT/'crates/signal-storage/Cargo.toml',
                               *list((ROOT/'crates/signal-query/src').rglob('*.rs')),ROOT/'crates/signal-query/Cargo.toml',
                               ROOT/'schemas/shared-control/v1.json',ROOT/'schemas/shared-control/001.sql',ROOT/'schemas/shared-control/002-functions.sql',ROOT/'schemas/shared-control/003-administration.sql',ROOT/'schemas/shared-control/004-restore.sql',ROOT/'schemas/shared-control/005-catalog.sql',ROOT/'schemas/shared-control/005-catalog.sha256',ROOT/'schemas/shared-control/007-finding-scope.sql',ROOT/'schemas/shared-control/007-finding-scope-catalog.sha256',ROOT/'schemas/shared-control/008-scoped-publication.sql',ROOT/'schemas/shared-control/008-scoped-publication-catalog.sha256',ROOT/'schemas/shared-control/008-scoped-publication-functions.sha256',ROOT/'schemas/shared-control/006-catalog-restore.sql',ROOT/'schemas/shared-control/006-catalog.sha256',ROOT/'schemas/shared-control/003-catalog.sha256',ROOT/'schemas/shared-control/004-catalog.sha256',ROOT/'schemas/shared-control/catalog-query.sql',ROOT/'schemas/shared-control/002-catalog.sha256'])}
        if args.server or args.standard:
            for source_name in ('tests/integration/shared-feed-provider.py', 'tests/integration/access-server-process.py', 'scripts/check-object-query.py','scripts/check-audit-role-composition.py','scripts/check-audit-receiver-permissions.py'):
                report['source_hashes'][source_name]=hashlib.sha256((ROOT/source_name).read_bytes()).hexdigest()
            for path in sorted([ROOT/'apps/signal-server/Cargo.toml', *list((ROOT/'apps/signal-server/src').rglob('*.rs')), *list((ROOT/'apps/signal-server/tests').rglob('*.rs')), ROOT/'crates/signal-buffer/Cargo.toml', *list((ROOT/'crates/signal-buffer/src').rglob('*.rs'))]):
                report['source_hashes'][str(path.relative_to(ROOT))]=hashlib.sha256(path.read_bytes()).hexdigest()
        if not (args.standard_only or args.standard_audit_only or args.standard_private_only or args.standard_restore_only):
            test_output=run(['cargo','test','--locked','--offline','-p','signal-control','--test','postgres','postgres_lease_authority_and_cancellation',
                 '--','--ignored','--exact','--nocapture'],150,env)
            qualify_test_output(test_output)
            catalogs=re.findall(r'^catalog4-catalog: ([0-9a-f]{64})$',test_output,re.MULTILINE)
            expected=(ROOT/'schemas/shared-control/005-catalog.sha256').read_text().strip()
            if catalogs!=[expected]:
                raise ValueError('actual revision4 catalog identity')
            report['catalog_profile_catalog_sha256']=expected
            report['checks'].append('actual_dynamic_catalog_populated_stopped_migration_replay_empty_quotas')
            report['checks'].append('actual_postgres_catalog_exact_parquet_datafusion_composition')
            catalogs=re.findall(r'^catalog5-catalog: ([0-9a-f]{64})$',test_output,re.MULTILINE)
            expected=(ROOT/'schemas/shared-control/006-catalog.sha256').read_text().strip()
            if catalogs!=[expected]:raise ValueError('actual revision5 catalog identity')
            report['restored_catalog_profile_catalog_sha256']=expected
            report['checks'].append('actual_coordinated_catalog_restore_preserved_pins_resumed_parquet_query')
            for label,artifact in [('source2','003'),('restored','004')]:
                catalogs=re.findall(r'^'+label+r'-catalog: ([0-9a-f]{64})$',test_output,re.MULTILINE)
                expected=(ROOT/f'schemas/shared-control/{artifact}-catalog.sha256').read_text().strip()
                if catalogs!=[expected]:
                    raise ValueError('actual '+label+' catalog identity')
                report[label+'_catalog_sha256']=expected

            scope_catalogs=re.findall(r'^scope7-catalog: ([0-9a-f]{64})$',test_output,re.MULTILINE)
            scope_expected=(ROOT/'schemas/shared-control/007-finding-scope-catalog.sha256').read_text().strip()
            if scope_catalogs!=[scope_expected]:
                raise ValueError('finding scope extension catalog identity')
            report['finding_scope_catalog_sha256']=scope_expected
            for label in ('catalog','functions'):
                expected=(ROOT/('schemas/shared-control/008-scoped-publication-'+label+'.sha256')).read_text().strip()
                if re.findall(r'^scope8-'+label+r': ([0-9a-f]{64})$',test_output,re.MULTILINE)!=[expected]:
                    raise ValueError('scoped publication exact '+label+' identity')
                report['scoped_publication_'+label+'_sha256']=expected
            report['scoped_publication_scope']='Actual owned PostgreSQL catalog4 atomic original core publication plus bounded host-derived facts and exact companion claims, late-write rollback, observed COMMIT cancellation/exact reconciliation, replay/difference/quota/startup/unknown-history checks with function-only runtime authority and persistent metadata restart. Catalog5 receives stopped008 schema/owner inspection only. Host event authentication, scoped Standard app recovery/reads, operational008 restore and full main startup remain unqualified.'

            report['finding_scope_host_api_scope']='Actual bounded stopped-owner library activation/enrollment, exact replay/current generation/whole original prefix/logical counters/startup replacement and original context/shutdown checks, including fresh restart. Owner reports are not native event authentication; startup floor capture adapter is source/component only, no Main/native admission/scoped read proof.'
            report['finding_scope_schema_scope']='Stopped owner-only additive schema on exact catalog4/5, native full rollback, captured activation/prefix and producer-floor records, denied runtime access and original history. Records are synthetic fixture owner reports, not authenticated host activation or scoped runtime/counter enforcement. Original metadata survives actual persistent restart.'
            if args.server:
                server_output=run(['cargo','test','--locked','--offline','-p','signal-server','--test','shared','postgres_server_publication_and_actual_query','--','--ignored','--exact','--nocapture'],30,env)
                qualify_server_output(server_output)
                report['checks'].append('actual_server_rule_parquet_atomic_publication_replay_query_and_orphan_fencing')
                report['checks'].append('actual_server_explicit_catalog_startup_scope_backend_existing_WAL_binding')
                report['checks'].append('actual_server_original_draft_request_SIGKILL_recovery_before_checkpoint_and_after_ACK')
                report['checks'].append('actual_server_scoped_original_claims_SIGKILL_recovery_and_stale_startup_missing_operation_hold')
                report['checks'].append('actual_server_scoped_observed_COMMIT_cancellation_original_claims_resolution_and_confirmed_WAL_checkpoint')
                report['server_scoped_recovery_scope']='Actual owned PostgreSQL and durable WAL original scoped schema2 draft/request through four producer SIGKILL boundaries and observed server COMMIT cancellation; byte-exact committed findings and companion claims resolve after current startup replacement, while a missing old-startup operation remains fenced with original slot and checkpoint held. Synthetic host authentication reports and emulated parent-retained object versions; no native authenticated admission, scoped reads, populated008 restore or Main readiness proof.'
                report['checks'].append('actual_shared_findings_original_wire_prefix_quota_and_cursor_classes')
                report['shared_findings_wire_scope']='Actual library adapter over PostgreSQL findings, original cursor/payload, finite caller seats and wire limit; ordinary Cargo route-denial regressions. No live authorized shared HTTP/provider roundtrip or main/scoped Standard readiness.'
                http_output=run(['python3','tests/integration/shared-feed-provider.py'],60,env)
                qualify_shared_http_output(http_output)
                report['checks'].append('actual_shared_feed_live_http_tls_introspection_and_durable_audit')
                report['checks'].append('actual_owner_enrollment_native_tls_http_WAL_floor_deadline_expiry_and_replay')
                report['checks'].append('actual_fully_reconciled_native_WAL_restart_original_enrollment_future_only_floor_and_pending_hold')
                report['checks'].append('actual_readonly_original_owner_enrollment_bootstrap_no_owner_mutation_and_foreign_scope_hold')
                report['checks'].append('actual_native_HTTP_rules_scoped_publication_legacy_unknown_original_request_WAL_resume')
                report['checks'].append('actual_native_TLS_scoped_read_explicit_SELECT_paired_before_limit_unknown_history_integrity_cancellation')
                report['checks'].append('actual_native_shared_scoped_HTTP_TLS_paired_before_limit_unknown_history_durable_audit_wire_limits_no_fallback')
                report['native_scoped_publication_scope']='Actual owner enrollment/native TLS HTTP admission, canonical rule findings, two-row legacy/new batch, real WAL saved scoped request/reopen, original missing-request reconciliation and atomic PostgreSQL facts before checkpoint2. Legacy finding bytes remain unknown; only canonical audit/account/resource facts from the authenticated new event are retained. Object versions are emulated and parent-retained; no Standard Main/READY, scoped reads, populated restore, actual AWS or native ARM64 claim.'
                report['native_shared_admission_scope']='Actual owner-produced SQL enrollment pin, native TLS introspection and loopback HTTP into grant-only durable WAL, captured legacy floor, bootstrap/raw/scope rejection, original request budget and native grant expiry, exact event replay. Continuation qualifies scoped rules/publication, exact original WAL request resume and explicitly SELECT-authorized scoped reads with native TLS grants. No Standard Main/READY, provider rotation or AWS/native ARM64 proof.'
                report['shared_findings_http_scope']='Actual loopback HTTP feed factory, TLS provider introspection, host policy, original PostgreSQL findings and synced audit decisions/completions. No main startup/scoped Standard readiness or external identity/destination proof.'
                report['server_publication_scope']='Owned monolith coordinator, explicit startup/WAL authority binding and durable exact request recovery through producer SIGKILL/confirmed checkpoint; emulated process-local object provider retained independently in parent. No main startup/global findings/private-consumer/custody or persistent server-object proof.'
            for path,digest in report['source_hashes'].items():
                if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest:
                    raise RuntimeError('fixture source changed during execution')
            report['checks'].append('actual_current_generation_scope_activation_enrollment_counters_replay_and_stale_startup_fencing')
            report['checks'].append('actual_stopped_finding_scope_schema_activation_enrollment_original_prefix_and_denied_runtime_access')
            report['checks'].extend(['actual_global_feed_explicit_select_authority_original_prefix_and_fixed_snapshot', 'actual_restored_global_feed_fresh_read_credentials_and_generation', 'actual_explicit_initialization_populated_checksummed_migration_and_rollback', 'actual_stopped_restore_fresh_generation_history_current_authority_and_custody', 'actual_lease_fencing_competition_permissions_and_cancelled_seats', 'actual_atomic_publication_receipts_exact_feed_and_global_dedup', 'actual_conflict_quota_rollback_concurrent_publication', 'actual_snapshot_exact_replay_expiry_reclamation_and_scope', 'actual_global_exact_version_retirement_and_retention_pins', 'actual_notification_attempt_fencing_and_charged_uncertain_history', 'actual_late_commit_reply_uncertainty_and_current_authority_resolution'])
        if args.standard_only or args.standard_audit_only or args.standard_private_only or args.standard_restore_only:
            report['scope']='Focused actual Standard executable, owned PostgreSQL TLS and persistent loopback S3 protocol simulation only; no full library/crash matrix, AWS, ARM64 or release proof'
        if args.standard:
            for source_name in ('tests/integration/standard-main-process.py','tests/integration/transport-server-process.py','scripts/fixtures/s3-query-server.py','apps/signal-server/tests/standard_main.rs','tests/fixtures/source-coverage/backend-vectors.json','scripts/check-object-query.py'):
                report['source_hashes'][source_name]=hashlib.sha256((ROOT/source_name).read_bytes()).hexdigest()
            for component in ('crates/signal-collector-sdk/src/audit','crates/signal-collector-sdk/src/transport'):
                for path in sorted((ROOT/component).rglob('*.rs')):report['source_hashes'][str(path.relative_to(ROOT))]=hashlib.sha256(path.read_bytes()).hexdigest()
            for source_name in ('crates/signal-collector-sdk/src/audit.rs','crates/signal-protocol/src/audit.rs'):
                report['source_hashes'][source_name]=hashlib.sha256((ROOT/source_name).read_bytes()).hexdigest()
            scenario='restore' if args.standard_restore_only else 'private' if args.standard_private_only else 'audit' if args.standard_audit_only else 'pipeline'
            if args.standard_kubernetes_image:
                for source in ('scripts/check-standard-kubernetes.py', 'scripts/check-kubernetes.py', 'scripts/fixtures/standard-kubernetes.py',
                               'deploy/helm/signal/templates/deployment.yaml', 'deploy/helm/signal/templates/configmap.yaml',
                               'deploy/helm/signal/values.yaml', 'deploy/helm/signal/values.schema.json', 'deploy/docker/Dockerfile'):
                    report['source_hashes'][source] = hashlib.sha256((ROOT/source).read_bytes()).hexdigest()
                standard_output=run(['python3','scripts/check-standard-kubernetes.py','--image',args.standard_kubernetes_image,
                                     '--postgres',name,'--server',str(standard_binary),'--output',str(out/'standard-process')],540,env)
                marker = 'Standard Kubernetes process gate passed'
            else:
                standard_output=run(['python3','tests/integration/standard-main-process.py','--scenario',scenario,'--server',str(standard_binary),'--output',str(out/'standard-process')],STANDARD_SECONDS,env)
                marker = 'Standard executable process gate passed'
            if standard_output.splitlines().count(marker) != 1:
                raise ValueError('actual Standard executable process qualification missing')
            standard_report=json.loads((out/'standard-process/report.json').read_text())
            if args.standard_kubernetes_image:
                if (standard_report.get('status') != 'passed_simulated'
                        or standard_report.get('wal_checkpoint') != 2 or standard_report.get('database_witness') != '2|0|2'
                        or standard_report.get('architecture') not in ('amd64', 'arm64')
                        or any(not isinstance(standard_report.get(key), str)
                               or not re.fullmatch(r'sha256:[0-9a-f]{64}', standard_report[key]) for key in ('image_id', 'fixture_image_id'))
                        or any(standard_report.get(key) is not True for key in
                               ('regular_config_mounts', 'sigkill_recovery', 'replacement_pod_pvc_recovery', 'owned_cluster_cleanup'))):
                    raise ValueError('Standard Kubernetes runtime acceptance missing')
                report['checks'].append('actual_Standard_kind_image_regular_Secret_mounts_original_WAL_PVC_SIGKILL_and_replacement_recovery')
                report['scope'] = standard_report['scope']
            elif args.standard_restore_only:
                qualify_standard_restore_report(standard_report,report['standard_binary_sha256'])
                if private_source_hashes(args.private_checkout)!=report['private_source_hashes']:raise RuntimeError('private consumer source changed during restore qualification')
                report['checks'].append('actual_fresh_scoped_restore_current_custody_private_cursor_generation_fencing_restored_native_publication')
                report['checks'].append('actual_restored_Standard_stopped_WAL_restricted_maintenance_holds_retirement_stale_fence')
                report['scope']=standard_report['scope']
            elif args.standard_private_only:
                qualify_standard_private_report(standard_report,report['standard_binary_sha256'])
                if private_source_hashes(args.private_checkout)!=report['private_source_hashes']:raise RuntimeError('private consumer source changed during qualification')
                report['checks'].append('actual_Standard_native_global_feed_private_cursor_atomic_outbox_three_attempt_notifications_restart')
                report['scope']='Focused actual Standard feed/private outbox and loopback notification qualification; no full library/crash matrix, populated restore, AWS, ARM64 or release acceptance'
            elif args.standard_audit_only:
                qualify_standard_audit_report(standard_report,report['standard_binary_sha256'])
                report['checks'].append('actual_Standard_independent_audit_required_outage_original_pending_replay_fresh_activation_empty_WAL')
            else:
                qualify_standard_report(standard_report,report['standard_binary_sha256'])
                report['checks'].append('actual_Standard_executable_native_TLS_ingest_persistent_versioned_S3_protocol_query_scoped_findings_global_feed_stopped_restart')
                report['checks'].append('actual_Standard_stopped_WAL_restricted_maintenance_holds_retirement_stale_fence')
            if args.standard_audit_only:report['scope']='Focused actual Standard startup with actual independent audit receiver, owned PostgreSQL TLS and persistent loopback S3 simulation; excludes pipeline/library/crash matrices, DAC, AWS, ARM64 and release qualification'
            report['standard_process_scope']=standard_report['scope']
        if args.matrix:
            report['failure_matrix']=qualify_matrix_output(test_output)
            def database_witness(database):
                tables=['store','partitions','commits','receipts','state','findings','outbox','snapshots','tombstones','principals','object_backends','object_scopes','object_pins','notification_attempts','migrations']
                if database in {'signal_restore_destination','signal_catalog_restore_destination'}:
                    tables.append('restore_record')
                if database in {'signal_catalog_profile','signal_catalog_restore_source','signal_catalog_restore_destination','signal_finding_scope_fixture'}:
                    tables.append('catalog_snapshots')
                entries=[]
                for table in tables:
                    entries.extend(["'"+table+"'", "(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM signal_control."+table+" t)"])
                if database=='signal_finding_scope_fixture':
                    for scope_table in ('profile','activation','producers','facts','requests'):
                        entries.extend(["'scope."+scope_table+"'", "(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM signal_finding_scope."+scope_table+" t)"])
                query="SET TimeZone='UTC'; SET bytea_output='hex'; SELECT encode(sha256(convert_to(jsonb_build_object("+','.join(entries)+")::text,'UTF8')),'hex')"
                value=run(['docker','exec',name,'psql','-X','-U','postgres','-d',database,'-At','-v','ON_ERROR_STOP=1','-c',query]).splitlines()[-1]
                if not re.fullmatch('[0-9a-f]{64}',value):
                    raise ValueError('persistent database witness')
                return value
            before={db:database_witness(db) for db in ['postgres','signal_restore_destination','signal_catalog_profile','signal_catalog_restore_source','signal_catalog_restore_destination','signal_finding_scope_fixture']}
            run(['docker','kill','--signal','KILL',name],10)
            run(['docker','start',name],10)
            # A persistent abrupt restart must replay and fsync every database;
            # the initial empty-container probe keeps its original allowance.
            run(['docker','exec',name,'sh','-c',READY_SCRIPT,'signal-recovery-ready','120'],65)
            restarted=json.loads(run(['docker','inspect',name]))[0]
            if restarted['Id']!=container or restarted['Image']!=image or restarted['Config']['Labels'].get('signal.shared.runtime')!=name:
                raise ValueError('restarted owned container identity')
            mounts=[m for m in restarted['Mounts'] if m['Destination']=='/var/lib/postgresql/data']
            if len(mounts)!=1 or mounts[0]['Type']!='volume' or mounts[0]['Name']!=volume_name:
                raise ValueError('restarted owned volume identity')
            bindings=restarted['NetworkSettings']['Ports']['5432/tcp']
            if len(bindings)!=1 or bindings[0]['HostIp']!='127.0.0.1':
                raise ValueError('restarted loopback publication')
            fixture=json.loads(config.read_text())
            fixture['port']=int(bindings[0]['HostPort'])
            if not 1<=fixture['port']<=65535:
                raise ValueError('restarted fixture port')
            config.write_text(json.dumps(fixture)+'\n')
            after={db:database_witness(db) for db in before}
            qualify_restart_witness(before,after)
            probe=run(['cargo','test','--locked','--offline','-p','signal-control','--test','postgres','postgres_matrix_restart_probe','--','--ignored','--exact','--nocapture'],30,env)
            qualify_restart_probe(probe)
            (out/'persistent-restart.json').write_text(json.dumps({'status':'passed_simulated','before':before,'after':after,'same_container':True,'same_volume':True,'abrupt_kill':True,'fresh_client_probe':True},indent=2)+'\n')
            report['checks'].extend(['actual_owned_producer_SIGKILL_and_reaped_children','actual_persistent_database_abrupt_restart_and_fresh_client'])
        for path,digest in report['source_hashes'].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest:
                raise RuntimeError('fixture source changed during restart qualification')
        report['status']='passed_simulated'
    except BaseException as exc:
        primary=exc
        report['failure']=str(exc)[:256]
        if created and count<61:
            try:
                run(['docker','logs','--tail','100',name],5)
            except BaseException:
                pass
    finally:
        if created:
            try:
                metadata=json.loads(run(['docker','inspect',name],cleanup=True))[0]
                if metadata['Config']['Labels'].get('signal.shared.runtime')!=name or metadata['Image']!=image:
                    raise RuntimeError('owned fixture identity changed')
                run(['docker','rm','--force',name],cleanup=True)
                report['container_removed']=True
            except BaseException as exc:
                report['cleanup_errors'].append(type(exc).__name__)
                report['status']='failed'
        if volume_created:
            try:
                if created and not report.get('container_removed'):
                    raise RuntimeError('owned container cleanup incomplete; retain volume')
                volume=json.loads(run(['docker','volume','inspect',volume_name],cleanup=True))[0]
                if volume['Name']!=volume_name or volume.get('Labels',{}).get('signal.shared.runtime')!=name:
                    raise RuntimeError('owned volume identity changed')
                run(['docker','volume','rm',volume_name],cleanup=True)
                report['volume_removed']=True
            except BaseException as exc:
                report['cleanup_errors'].append(type(exc).__name__)
                report['status']='failed'
        report['elapsed_seconds']=time.monotonic()-began
        report['commands']=count
        within_budget = (0 <= report['elapsed_seconds'] <= fixture_seconds if args.standard_kubernetes_image
                         else elapsed_within_fixture_budget(report['elapsed_seconds'],combined_standard=combined_standard))
        if not within_budget:
            report['status']='failed'
        (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:value for key,value in report.items() if key not in ('source_hashes','private_source_hashes')}))
    if primary:
        raise primary
    if report['status']!='passed_simulated':
        raise RuntimeError('shared fixture final acceptance failed')

if __name__=='__main__':
    main()

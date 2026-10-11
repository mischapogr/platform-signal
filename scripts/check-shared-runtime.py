#!/usr/bin/env python3
"""Qualify explicit administration and shared-control primitives against owned PostgreSQL, not HA readiness."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SECONDS = 240


def elapsed_within_fixture_budget(elapsed):
    return type(elapsed) in (int, float) and 0 <= elapsed <= FIXTURE_SECONDS

# One charged Docker command; each connection probe and the retry count are finite.
# This owned-container loop cannot consume the four cleanup command slots.
READY_SCRIPT = '''attempt=0
while [ "$attempt" -lt 60 ]; do
    pg_isready -q -t 1 -h 127.0.0.1 -U postgres
    result=$?
    case "$result" in
        0) exit 0 ;;
        1|2) ;;
        *) exit "$result" ;;
    esac
    attempt=$((attempt+1))
    if [ "$attempt" -lt 60 ]; then sleep .5; fi
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
    if (len(output.encode('utf-8')) > 65536
            or output.splitlines().count('phase: actual-shared-feed-live-http-tls-provider-durable-audit-qualified') != 1
            or not re.search(r'test result: ok\. 1 passed; 0 failed; 0 ignored;', output)):
        raise ValueError('live shared HTTP/provider/audit qualification missing or ambiguous')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', default='postgres:17.5-alpine')
    parser.add_argument('--matrix', action='store_true', help='owned persistent volume and abrupt database restart qualification')
    parser.add_argument('--server', action='store_true', help='actual monolithic server publication/rules/query coordinator qualification')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('shared_runtime_command', ROOT/'scripts/check-native-qualification.py')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    began = time.monotonic()
    # Expanded control/restore and server crash matrices need separate harness
    # headroom. This never extends any production operation context or SQL timeout.
    deadline = began+FIXTURE_SECONDS
    name = 'signal-shared-runtime-'+uuid.uuid4().hex
    password = 'synthetic-control-'+uuid.uuid4().hex
    image = None
    created = False
    volume_created = False
    volume_name = name+'-pgdata'
    count = 0
    report = {'status':'failed','scope':'owned PostgreSQL administration/lease/publication/receipt/replay/snapshot/retirement/retention/notification/coordinated-stopped-restore/permission/cancellation primitives only; shared runtime remains unfinished',
              'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'container_name':name, 'checks':[], 'cleanup_errors':[]}
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
        report['source_hashes']={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted([ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'scripts/check-shared-runtime.py',
                               *list((ROOT/'crates/signal-control').rglob('*.rs')),ROOT/'crates/signal-control/Cargo.toml',
                               *list((ROOT/'crates/signal-storage/src').rglob('*.rs')),ROOT/'crates/signal-storage/Cargo.toml',
                               *list((ROOT/'crates/signal-query/src').rglob('*.rs')),ROOT/'crates/signal-query/Cargo.toml',
                               ROOT/'schemas/shared-control/v1.json',ROOT/'schemas/shared-control/001.sql',ROOT/'schemas/shared-control/002-functions.sql',ROOT/'schemas/shared-control/003-administration.sql',ROOT/'schemas/shared-control/004-restore.sql',ROOT/'schemas/shared-control/005-catalog.sql',ROOT/'schemas/shared-control/005-catalog.sha256',ROOT/'schemas/shared-control/007-finding-scope.sql',ROOT/'schemas/shared-control/007-finding-scope-catalog.sha256',ROOT/'schemas/shared-control/008-scoped-publication.sql',ROOT/'schemas/shared-control/008-scoped-publication-catalog.sha256',ROOT/'schemas/shared-control/008-scoped-publication-functions.sha256',ROOT/'schemas/shared-control/006-catalog-restore.sql',ROOT/'schemas/shared-control/006-catalog.sha256',ROOT/'schemas/shared-control/003-catalog.sha256',ROOT/'schemas/shared-control/004-catalog.sha256',ROOT/'schemas/shared-control/catalog-query.sql',ROOT/'schemas/shared-control/002-catalog.sha256'])}
        if args.server:
            for source_name in ('tests/integration/shared-feed-provider.py', 'tests/integration/access-server-process.py', 'scripts/check-object-query.py'):
                report['source_hashes'][source_name]=hashlib.sha256((ROOT/source_name).read_bytes()).hexdigest()
            for path in sorted([ROOT/'apps/signal-server/Cargo.toml', *list((ROOT/'apps/signal-server/src').rglob('*.rs')), *list((ROOT/'apps/signal-server/tests').rglob('*.rs')), ROOT/'crates/signal-buffer/Cargo.toml', *list((ROOT/'crates/signal-buffer/src').rglob('*.rs'))]):
                report['source_hashes'][str(path.relative_to(ROOT))]=hashlib.sha256(path.read_bytes()).hexdigest()
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
            http_output=run(['python3','tests/integration/shared-feed-provider.py'],30,env)
            qualify_shared_http_output(http_output)
            report['checks'].append('actual_shared_feed_live_http_tls_introspection_and_durable_audit')
            report['shared_findings_http_scope']='Actual loopback HTTP feed factory, TLS provider introspection, host policy, original PostgreSQL findings and synced audit decisions/completions. No main startup/scoped Standard readiness or external identity/destination proof.'
            report['server_publication_scope']='Owned monolith coordinator, explicit startup/WAL authority binding and durable exact request recovery through producer SIGKILL/confirmed checkpoint; emulated process-local object provider retained independently in parent. No main startup/global findings/private-consumer/custody or persistent server-object proof.'
        for path,digest in report['source_hashes'].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest:
                raise RuntimeError('fixture source changed during execution')
        report['checks'].append('actual_current_generation_scope_activation_enrollment_counters_replay_and_stale_startup_fencing')
        report['checks'].append('actual_stopped_finding_scope_schema_activation_enrollment_original_prefix_and_denied_runtime_access')
        report['checks'].extend(['actual_global_feed_explicit_select_authority_original_prefix_and_fixed_snapshot', 'actual_restored_global_feed_fresh_read_credentials_and_generation', 'actual_explicit_initialization_populated_checksummed_migration_and_rollback', 'actual_stopped_restore_fresh_generation_history_current_authority_and_custody', 'actual_lease_fencing_competition_permissions_and_cancelled_seats', 'actual_atomic_publication_receipts_exact_feed_and_global_dedup', 'actual_conflict_quota_rollback_concurrent_publication', 'actual_snapshot_exact_replay_expiry_reclamation_and_scope', 'actual_global_exact_version_retirement_and_retention_pins', 'actual_notification_attempt_fencing_and_charged_uncertain_history', 'actual_late_commit_reply_uncertainty_and_current_authority_resolution'])
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
            run(['docker','exec',name,'sh','-c',READY_SCRIPT],35)
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
        if not elapsed_within_fixture_budget(report['elapsed_seconds']):
            report['status']='failed'
        (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:value for key,value in report.items() if key!='source_hashes'}))
    if primary:
        raise primary
    if report['status']!='passed_simulated':
        raise RuntimeError('shared fixture final acceptance failed')

if __name__=='__main__':
    main()

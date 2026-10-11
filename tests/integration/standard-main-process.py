#!/usr/bin/env python3
"""Actual Standard monolith + owned PostgreSQL TLS/persistent S3 simulation.

The parent supplies its owned PostgreSQL fixture. Owner provisioning occurs only
in the explicit offline Rust fixture. No AWS, ARM64 or release qualification.
"""
import argparse
import base64
import hashlib
import http.server
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[2]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
def binary_digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
BASE = module('standard_object_fixture', 'scripts/check-object-query.py')
ACCESS = module('standard_access_fixture', 'tests/integration/access-server-process.py')
TRANSPORT = module('standard_transport_fixture', 'tests/integration/transport-server-process.py')

class Run(BASE.Run):
    def __init__(self, out, binary, fixture):
        super().__init__(out, binary,child_capacity=3,log_capacity=24)
        self.control = fixture
        self.provider_calls = 0
        self.pki = TRANSPORT.Run(binary, binary, out / 'pki')
        ca = self.pki.ca('standard')
        server = self.pki.leaf(ca, 'server', 'serverAuth')
        client = self.pki.leaf(ca, 'client', 'clientAuth')
        crl = self.pki.crl(ca, 'current')
        self.tls = self.pki.material('server', server, [ca], [crl])
        self.context = self.pki.context(ca, client)
        self.provider = self.thread = None
        self.server_config = None

    def offline(self, phase, label=None):
        label=label or "offline-"+phase
        environment = {k:v for k,v in os.environ.items() if not k.startswith('SIGNAL_')}
        environment.update(SIGNAL_CONTROL_FIXTURE=str(self.control), SIGNAL_STANDARD_ROOT=str(self.out),
                           SIGNAL_STANDARD_BACKEND=self.fixture_id, SIGNAL_STANDARD_PHASE=phase)
        if getattr(self,'audit_mode',False):environment['SIGNAL_STANDARD_AUDIT']='true'
        child = self.spawn(['cargo','test','--locked','--offline','-p','signal-server','--all-features',
                            '--test','standard_main','standard_offline_fixture','--','--ignored','--exact','--nocapture'],
                           environment, label)
        try:
            child.wait(timeout=30)
            if child.returncode:
                raise RuntimeError('offline Standard fixture failed: '+phase)
        finally:
            if child.poll() is None:
                child.kill(); child.wait(timeout=2)
            self.reap_log(child); self.reaped(child)
        output=(self.out/(label+'.log')).read_text()
        markers={
            'prepare':['phase: Standard-producer-verified-TLS-owner-reader-table-column-DDL-precancel-qualification-complete',
                       'phase: offline-Standard-owner-enrollment-and-least-privilege-provisioned'],
            'restore_scope':['phase: Standard-fresh-trusted-scoped-restore-current-custody-consumer-gate-generation-original-bytes-qualified',
                             'phase: Standard-scoped-restore-DDL-error-and-observed-cancellation-original-inventory-rollback-qualified',
                             'phase: Standard-scoped-restore-observed-COMMIT-caller-cancellation-current-resolution-consumer-refusal-qualified'],
            'verify_restored':['phase: Standard-restored-native-publication-original-WAL-floor-and-private-cursor-qualified'],
            'restore_scope_stage':['phase: Standard-populated-scoped-restore-stage-core-only-denial-counter-corruption-qualified'],
            'verify_audit_empty':['phase: Standard-audit-lifecycle-original-empty-DB-WAL-floor-checkpoint-qualified'],
            'verify':['phase: Standard-process-exact-findings-facts-DB-WAL-checkpoint-original-floor-qualified'],
            'retirement':['phase: Standard-stopped-original-WAL-explicit-holds-retirement-stale-fence-qualified'],
            'retirement_restored':['phase: Standard-restored-stopped-original-WAL-explicit-holds-retirement-stale-fence-qualified'],
            'verify_crash_saved':['phase: Standard-SIGKILL-original-prepared-request-retained-WAL3-DB-checkpoint2-qualified'],
            'verify_crash_recovered':['phase: Standard-original-saved-request-manifest-once-DB-WAL-checkpoint3-qualified'],
            'verify_unprepared_before':['phase: Standard-native-SIGKILL-unprepared-WAL4-checkpoint3-no-recovery-qualified'],
            'verify_unprepared_after':['phase: Standard-unprepared-native-restart-held-original-event-floor-checkpoints-unchanged-qualified'],
        }[phase]
        if phase=='prepare':
            matches=re.findall(r'Running tests/standard_main\.rs \((target/debug/deps/standard_main-[0-9a-f]+)\)',output)
            if len(matches)!=1:raise RuntimeError('owned offline test executable not uniquely bound')
            self.offline_binary=(ROOT/matches[0]).resolve()
            if self.offline_binary.is_symlink() or not self.offline_binary.is_file() or not 0<self.offline_binary.stat().st_size<=2*1024**3:
                raise RuntimeError('owned offline test executable shape')
        if any(output.splitlines().count(marker)!=1 for marker in markers):
            raise RuntimeError('offline Standard qualification marker missing or duplicated: '+phase)

    def start_provider(self):
        fixture = BASE.read_json(self.control)
        certs = Path(fixture['root_der']).parent
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args): pass
            def do_POST(self):
                self.connection.settimeout(1)
                owner.provider_calls += 1
                size = int(self.headers.get('Content-Length','0'))
                expected = 'Basic '+base64.b64encode(b'synthetic-standard:synthetic-standard-idp-secret').decode()
                if owner.provider_calls>64 or self.path!='/token' or not 0<size<=16384 or self.headers.get('Authorization')!=expected:
                    self.send_error(400);return
                token = urllib.parse.parse_qs(self.rfile.read(size).decode()).get('token',[''])[0]
                payload = {'active':token in ('global','read-a','read-b'),'iss':'https://identity.example.test',
                           'sub':token,'aud':'signal','exp':int(time.time())+60,'token_type':'Bearer','roles':['ignored'],'scope':'admin'}
                body = json.dumps(payload).encode()
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certs/'leaf.pem',certs/'leaf.key')
        self.provider = ACCESS.FiniteTLSProvider(('127.0.0.1',0),Handler,context)
        self.thread = threading.Thread(target=self.provider.serve_forever,kwargs={'poll_interval':.05})
        ACCESS.start_provider_thread(self.thread)
        all_scope = {name:{'mode':'all'} for name in ('sources','accounts','resources')}
        roles=[{'id':'global','permissions':[{'operation':op,'scope':all_scope} for op in ('ingest_events','query_events','read_findings','read_findings_feed','read_coverage')]}]
        bindings=[{'issuer':'https://identity.example.test','subject':'global','roles':['global']}]
        for account in ('a','b'):
            scope={'sources':{'mode':'only','values':['query-simulation']},'accounts':{'mode':'only','values':[account]},'resources':{'mode':'only','values':['host-'+account]}}
            roles.append({'id':'read-'+account,'permissions':[{'operation':op,'scope':scope} for op in ('query_events','read_findings')]})
            bindings.append({'issuer':'https://identity.example.test','subject':'read-'+account,'roles':['read-'+account]})
        config={'schema_version':1,'endpoint':f'https://127.0.0.1:{self.provider.server_port}/token','client_id':'synthetic-standard',
                'issuer':'https://identity.example.test','audience':'signal','lease_seconds':30,'workers':1,'request_timeout_ms':1000,
                'roots_der_base64':[base64.b64encode(Path(fixture['root_der']).read_bytes()).decode()],
                'policy':{'schema_version':1,'roles':roles,'bindings':bindings}}
        self.access=self.pki.private/'access.json'
        self.access.write_text(json.dumps(config));self.access.chmod(0o600)
        vectors=json.loads((ROOT/'tests/fixtures/source-coverage/backend-vectors.json').read_text())
        coverage={'schema_version':1,'directory':str(self.out/'coverage-root'),
                  'limits':{'max_payloads':128,'max_identities':128,'max_bindings':32,'max_ledger_bytes':4194304,
                            'max_database_pages':1024,'max_journal_bytes':146800640,'operation_capacity':4,
                            'transient_memory_bytes':16777216,'worker_memory_bytes':8388608,
                            'max_vm_steps':10000000,'operation_timeout_ms':5000},
                  'scopes':[{'binding_json':json.dumps(vectors['bindings'][0]['input']),
                             'profile_json':json.dumps(vectors['profiles'][0]['input']),
                             'authority_revision':'synthetic-standard-v1',
                             'identity':{'scope_id':'standard-coverage','account_id':None,
                                         'writer_issuer':'https://identity.example.test','writer_subject':'global'},
                             'max_report_age_seconds':60,'max_clock_skew_seconds':2,
                             'payload_retention_seconds':300,'identity_retention_seconds':600}]}
        self.coverage=self.out/'coverage.json';self.coverage.write_text(json.dumps(coverage));self.coverage.chmod(0o600)
        self.password=fixture['password']

    def env(self):
        environment=super().env()
        environment.pop('SIGNAL_API_TOKEN')
        environment.update(SIGNAL_SHARED_CONFIG=str(self.out/'shared.json'),SIGNAL_TLS_CONFIG=str(self.tls),
                           SIGNAL_ACCESS_CONFIG=str(self.access),SIGNAL_IDENTITY_CLIENT_SECRET='synthetic-standard-idp-secret',
                           SIGNAL_STANDARD_PRODUCER_PASSWORD=self.password,SIGNAL_STANDARD_READER_PASSWORD=self.password,
                           SIGNAL_SHUTDOWN_TIMEOUT_MS='5000',SIGNAL_QUERY_TIMEOUT_MS='5000',SIGNAL_COVERAGE_CONFIG=str(self.coverage))
        return environment

    def request(self,path,token='global',method='GET',body=None,extra_headers=None):
        return TRANSPORT.absolute_request(self.context,self.server_port,path,token,timeout=2,method=method,body=json.dumps(body).encode() if body is not None else None,extra_headers=extra_headers)

    def bootstrap_coverage(self):
        child=self.spawn([str(self.binary),'--initialize-coverage'],self.env(),'coverage-bootstrap')
        try:
            child.wait(timeout=7)
            if child.returncode:raise RuntimeError('explicit Standard coverage initialization failed')
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=2)
            self.reap_log(child);self.reaped(child)

    def check_coverage(self):
        status,_=self.request('/v1/coverage/metrics',extra_headers={'x-signal-coverage-scope':'standard-coverage'})
        if status!=200:raise RuntimeError('Standard selected native coverage read failed')
        status,_=self.request('/v1/coverage/metrics',token='read-a',extra_headers={'x-signal-coverage-scope':'standard-coverage'})
        if status!=403:raise RuntimeError('Standard coverage read permission boundary failed')

    def start_server(self,overrides=None):
        self.generation+=1
        environment=self.env()
        if overrides:environment.update(overrides)
        self.server=self.spawn([str(self.binary)],environment,'standard-server-'+str(self.generation))
        def ready():
            if self.server.poll() is not None: raise RuntimeError('Standard startup failed')
            try:return self.request('/readyz')[0]==200
            except (OSError,TimeoutError):return False
        self.wait(ready,seconds=10)

    def reject_producer(self,user):
        path=self.out/'shared.json';original=path.read_bytes();document=json.loads(original)
        document['database']['producer_user']=user
        if user==document['database']['reader_user']:
            document['database']['reader_user']='synthetic-unused-reader'
        path.write_text(json.dumps(document))
        child=None
        try:
            child=self.spawn([str(self.binary)],self.env(),'denied-producer-'+user)
            child.wait(timeout=5)
            self.reap_log(child);self.reaped(child)
            log=(self.out/('denied-producer-'+user+'.log')).read_text()
            if child.returncode==0 or 'shared control authority is stale or denied' not in log:
                raise RuntimeError('Standard failed to reject producer privilege boundary')
        finally:
            path.write_bytes(original)
            if child is not None and child.poll() is None:
                child.kill();child.wait(timeout=2);self.reap_log(child);self.reaped(child)

    def interrupted_startup(self):
        # Accept the PostgreSQL TLS negotiation but deliberately never reply.
        # The accept event proves Main is in startup with control workers owned.
        path=self.out/'shared.json';original=path.read_bytes();document=json.loads(original)
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(3)
        document['database']['port']=listener.getsockname()[1]
        path.write_text(json.dumps(document));child=None;connection=None
        try:
            child=self.spawn([str(self.binary)],self.env(),'interrupted-startup')
            connection,_=listener.accept()
            began=time.monotonic();child.send_signal(signal.SIGTERM);child.wait(timeout=3)
            self.reap_log(child);self.reaped(child)
            log=(self.out/'interrupted-startup.log').read_text()
            if child.returncode==0 or 'Standard startup resources drained' not in log or 'cleanup failed' in log:
                raise RuntimeError('Standard interrupted startup did not explicitly drain resources')
            self.startup_interruption_seconds=time.monotonic()-began
        finally:
            path.write_bytes(original);listener.close()
            if connection is not None:connection.close()
            if child is not None and child.poll() is None:
                child.kill();child.wait(timeout=2);self.reap_log(child);self.reaped(child)

    def reject_occupied_listener(self, invalid_cache=False, missing_coverage=False):
        # A bind failure happens after WAL, publisher, query and identity exist.
        # Keep the original lease policy: the caller waits for expiry beforehand.
        listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(('127.0.0.1',self.server_port));listener.listen(1);child=None
        try:
            began=time.monotonic()
            label='missing-coverage-startup' if missing_coverage else ('invalid-cache-startup' if invalid_cache else 'occupied-listener-startup')
            environment=self.env()
            if invalid_cache:environment['SIGNAL_S3_CACHE_FILES']='0'
            if missing_coverage:
                config=json.loads(self.coverage.read_text());config['directory']=str(self.out/'uninitialized-coverage-root')
                rejected_config=self.out/'uninitialized-coverage.json';rejected_config.write_text(json.dumps(config));rejected_config.chmod(0o600)
                environment['SIGNAL_COVERAGE_CONFIG']=str(rejected_config)
            child=self.spawn([str(self.binary)],environment,label)
            child.wait(timeout=5);self.reap_log(child);self.reaped(child)
            log=(self.out/(label+'.log')).read_text()
            if child.returncode==0 or 'Standard startup resources drained' not in log or 'cleanup failed' in log:
                raise RuntimeError('Standard late startup failure did not explicitly drain resources')
            if missing_coverage:
                if 'coverage filesystem operation failed' not in log or (self.out/'uninitialized-coverage-root').exists():
                    raise RuntimeError('Standard silently initialized or bypassed selected coverage')
                self.missing_coverage_failure_seconds=time.monotonic()-began
            elif invalid_cache:
                if 'bounded query materialization' not in log:raise RuntimeError('invalid cache did not reach validation boundary')
                self.invalid_cache_failure_seconds=time.monotonic()-began
            else:self.startup_failure_seconds=time.monotonic()-began
        finally:
            listener.close()
            if child is not None and child.poll() is None:
                child.kill();child.wait(timeout=2);self.reap_log(child);self.reaped(child)

    def crash_original_publication(self):
        environment={k:v for k,v in os.environ.items() if not k.startswith('SIGNAL_')}
        environment.update(SIGNAL_CONTROL_FIXTURE=str(self.control),SIGNAL_STANDARD_ROOT=str(self.out),
                           SIGNAL_STANDARD_BACKEND=self.fixture_id,SIGNAL_STANDARD_PHASE='crash_lock')
        child=self.spawn([str(self.offline_binary),'--ignored','--exact','standard_offline_fixture','--nocapture'],
                         environment,'owned-publication-lock')
        try:
            self.wait(lambda:(self.out/'crash-lock-ready').is_file(),seconds=3)
            event={'id':str(uuid.uuid4()),'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                   'source':{'type':'query-simulation'},'severity':'error','message':'Standard original crash operation',
                   'resource':{'kind':'host','id':'host-a','account_id':'a'}}
            if self.request('/v1/events',method='POST',body=event)[0]!=202:raise RuntimeError('crash event not durably admitted')
            recovery=self.server_root/'wal/recovery'
            observed={}
            def saved():
                if self.server.poll() is not None:raise RuntimeError('producer exited before actual SIGKILL')
                if not recovery.is_file():return False
                with recovery.open('rb') as stream:frame=stream.read(4*1024*1024+65)
                if not 64<len(frame)<=4*1024*1024+64 or frame[:8]!=b'SIGREC01':raise RuntimeError('saved original recovery frame bounds')
                if int.from_bytes(frame[24:32],'little')!=len(frame)-64 or hashlib.sha256(frame[:32]+frame[64:]).digest()!=frame[32:64]:
                    raise RuntimeError('saved original recovery frame integrity')
                entry=json.loads(frame[64:])
                if entry['phase']['state']!='scoped_prepared':return False
                if not (self.out/'crash-commit-blocked').is_file():return False
                observed.update(frame=frame,entry=entry);return True
            self.wait(saved,seconds=3)
            (self.out/'crash-recovery-frame.bin').write_bytes(observed['frame'])
            if self.checkpoint()!=2:raise RuntimeError('crash advanced checkpoint before blocked publication')
            self.stop('server',kill=True);killed=time.monotonic()
            child.wait(timeout=13);self.reap_log(child);self.reaped(child)
            if child.returncode:raise RuntimeError('owned publication lock did not release normally')
            self.offline('verify_crash_saved')
            oracle=json.loads((self.out/'crash-saved.json').read_text())
            if bytes(oracle['record_sha256'])!=observed['frame'][32:64]:raise RuntimeError('original saved slot changed after crash')
            time.sleep(max(0,killed+16-time.monotonic()))
            self.start_server()
            ids={row['id'] for row in self.events()['events']}
            if event['id'] not in ids or len(ids)!=3:raise RuntimeError('original operation did not recover exactly once')
            self.stop('server');self.offline('verify_crash_recovered')
            request=observed['entry']['phase']['request']['publication']
            self.crash_request_id=request['id'];self.crash_event_id=event['id']
            self.record('actual_Standard_SIGKILL_saved_original_request_manifest_once_checkpoint3',
                        event_id=event['id'],request_id=request['id'])
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=2);self.reap_log(child);self.reaped(child)

    def hold_unprepared_native_wal(self):
        # Lease expiry is required after the preceding failed start.
        time.sleep(16)
        self.start_server({'SIGNAL_STORAGE_FLUSH_MS':'60000'})
        event={'id':str(uuid.uuid4()),'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
               'source':{'type':'query-simulation'},'severity':'error','message':'Standard native unprepared event',
               'resource':{'kind':'host','id':'host-a','account_id':'a'}}
        if self.request('/v1/events',method='POST',body=event)[0]!=202:raise RuntimeError('unprepared native event not admitted')
        self.stop('server',kill=True)
        if (self.server_root/'wal/recovery').exists():raise RuntimeError('unprepared qualification raced with saved publication')
        self.offline('verify_unprepared_before')
        before=json.loads((self.out/'unprepared-before.json').read_text())
        if before['event']['id']!=event['id']:raise RuntimeError('native pending original event identity')
        time.sleep(16)
        child=self.spawn([str(self.binary)],self.env(),'denied-unprepared-native-restart')
        try:
            child.wait(timeout=5);self.reap_log(child);self.reaped(child)
            log=(self.out/'denied-unprepared-native-restart.log').read_text()
            if child.returncode==0 or 'shared control authority is stale or denied' not in log or 'Standard startup resources drained' not in log:
                raise RuntimeError('unprepared native WAL must hold startup and explicitly drain')
            self.offline('verify_unprepared_after')
            after=json.loads((self.out/'unprepared-after.json').read_text())
            if before!=after:raise RuntimeError('held startup changed original unprepared native row')
            self.pending_event_id=event['id']
            self.record('actual_Standard_unprepared_native_WAL_restart_held_original_row_checkpoint3',event_id=event['id'])
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=2);self.reap_log(child);self.reaped(child)

    def events(self):
        status,body=self.request('/v1/events?limit=100')
        if status!=200:
            try:metrics_status,metrics=self.request('/metrics/shared')
            except (OSError,TimeoutError):metrics_status,metrics=None,b'unavailable after query failure'
            diagnostic={'query_status':status,'query_body':body.decode(errors='replace')[:4096],
                        'metrics_status':metrics_status,'metrics':metrics.decode(errors='replace')[:16384]}
            (self.out/'query-failure.json').write_text(json.dumps(diagnostic,indent=2)+'\n')
            raise RuntimeError('Standard query status '+str(status))
        return json.loads(body)

    def run(self):
        self.start_fixture();self.start_provider();self.offline('prepare');self.bootstrap_coverage()
        for user in ('signal_migrator','signal_standard_reader'):self.reject_producer(user)
        self.interrupted_startup()
        self.start_server()
        if self.events()['events']!=[]:raise RuntimeError('Standard empty committed catalog')
        self.check_coverage()
        ids=[]
        for account in ('a','b'):
            event={'id':str(uuid.uuid4()),'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                   'source':{'type':'query-simulation'},'severity':'error','message':'Standard native '+account,
                   'resource':{'kind':'host','id':'host-'+account,'account_id':account},'attributes':{'nested':{'preserve':[1,True,'value']}}}
            status,body=self.request('/v1/events',method='POST',body=event)
            if status!=202 or json.loads(body)['event_ids']!=[event['id']]:raise RuntimeError('Standard native admission')
            ids.append(event['id'])
        self.wait(lambda:len(self.events()['events'])==2)
        if {e['id'] for e in self.events()['events']}!=set(ids):raise RuntimeError('Standard canonical query identities')
        for account in ('a','b'):
            status,body=self.request('/v1/events?limit=100','read-'+account)
            if status!=200 or [e['id'] for e in json.loads(body)['events']]!=[ids[0 if account=='a' else 1]]:
                raise RuntimeError('Standard paired scoped event query')
            status,body=self.request('/v1/findings?limit=1','read-'+account)
            data=json.loads(body)
            if status!=200 or len(data['findings'])!=1 or data['findings'][0]['event_ids']!=[ids[0 if account=='a' else 1]]:raise RuntimeError('Standard paired scoped findings')
            status,_=self.request('/v1/findings/feed?limit=2','read-'+account)
            if status!=403:raise RuntimeError('Standard global feed permission separation')
        status,body=self.request('/v1/findings/feed?after=begin&limit=2')
        (self.out/'feed-response.json').write_bytes(body[:65536])
        if status!=200 or len(json.loads(body)['findings'])!=2:raise RuntimeError('Standard global findings feed')
        status,body=self.request('/metrics/shared')
        required=(b'signal_shared_producer_queue_capacity 32',b'signal_shared_query_io_queue_capacity 1',
                  b'signal_shared_query_codec_queue_capacity 1',b'signal_shared_findings_callers_capacity 4',
                  b'signal_shared_feed_callers_capacity 4',b'signal_shared_query_io_rejected_total 0')
        if status!=200 or any(row not in body for row in required):raise RuntimeError('Standard shared queue metrics')
        self.stop('server');self.offline('verify')
        self.record('actual_Standard_native_TLS_ingest_versioned_S3_query_scoped_findings_global_feed_graceful_shutdown',event_ids=ids)
        # The original database-clock lease must expire; no owner overwrite/DDL.
        time.sleep(16)
        self.offline('retirement')
        self.record('actual_Standard_stopped_original_WAL_explicit_holds_exact_retirement_stale_fence')
        # Maintenance also has a real finite lease; do not override its owner.
        time.sleep(16)
        self.start_server()
        if {e['id'] for e in self.events()['events']}!=set(ids):raise RuntimeError('Standard stopped restart query identities')
        self.check_coverage()
        self.record('actual_Standard_stopped_restart_original_enrollment_and_current_query')
        self.crash_original_publication()
        time.sleep(16)
        self.reject_occupied_listener()
        time.sleep(16)
        self.reject_occupied_listener(invalid_cache=True)
        time.sleep(16)
        self.reject_occupied_listener(missing_coverage=True)
        self.offline('verify_crash_recovered','offline-verify-after-startup-failure')
        self.hold_unprepared_native_wal()

    def cleanup_all(self):
        errors=[]
        try:
            if self.cleanup():errors.append("owned process cleanup")
        except BaseException:errors.append('owned process cleanup')
        try:
            if self.provider is not None:ACCESS.stop_provider(self.provider,self.thread)
        except BaseException:errors.append('provider cleanup')
        shutil.rmtree(self.pki.private)
        if errors:raise RuntimeError(', '.join(errors))

class PrivateRun(Run):
    """External private application consumes the actual native Standard feed."""
    def __init__(self,*args):
        super().__init__(*args)
        self.private=Path(os.environ['SIGNAL_STANDARD_PRIVATE_CHECKOUT']).resolve(strict=True)
        if self.private.is_relative_to(ROOT) or not (self.private/'tests/standard_main.rs').is_file():
            raise RuntimeError('separate private Standard consumer fixture required')
        self.notifications=None;self.notification_thread=None;self.notification_rows={};self.notification_calls=0

    def start_notifications(self):
        owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_args):pass
            def do_POST(self):
                self.connection.settimeout(1);owner.notification_calls+=1
                size=int(self.headers.get('Content-Length','0'));key=self.headers.get('Idempotency-Key','')
                if owner.notification_calls>8 or not key or not 0<size<=65536 or self.headers.get('Authorization')!='Bearer synthetic-standard-destination-token':
                    self.send_error(400);return
                body=self.rfile.read(size)
                if len(body)!=size or (key not in owner.notification_rows and len(owner.notification_rows)>=2):
                    self.send_error(400);return
                entries=owner.notification_rows.setdefault(key,[]);entries.append(body)
                if len(entries)==1:
                    # Accepted bytes, then lost reply. Original payload/key must survive.
                    self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();self.close_connection=True;return
                code=429 if len(entries)==2 else 200
                self.send_response(code);self.send_header('Content-Length','2');self.send_header('Retry-After','1');self.end_headers();self.wfile.write(b'ok')
        self.notifications=http.server.HTTPServer(('127.0.0.1',0),Handler)
        self.notification_thread=threading.Thread(target=self.notifications.serve_forever,daemon=True);self.notification_thread.start()

    def consume(self,phase):
        config=self.out/'private-consumer.json';document=json.loads(config.read_text());document['phase']=phase;BASE.write_json(config,document)
        environment={k:v for k,v in os.environ.items() if not k.startswith('SIGNAL_')}
        environment['SIGNAL_STANDARD_PRIVATE_CONFIG']=str(config)
        child=self.spawn(['cargo','test','--manifest-path',str(self.private/'Cargo.toml'),'--locked','--offline',
                          '--test','standard_main','standard_main_native_feed_private_outbox','--','--ignored','--exact','--nocapture'],
                          environment,'private-consumer-'+phase)
        try:
            child.wait(timeout=30);self.reap_log(child);self.reaped(child)
            output=(self.out/('private-consumer-'+phase+'.log')).read_text()
            if child.returncode or output.splitlines().count('phase: Standard-native-private-outbox-'+phase+'-qualified')!=1:
                raise RuntimeError('actual external private consumer failed: '+phase)
            matches=re.findall(r'Running tests/standard_main\.rs \(([^)]+/target/debug/deps/standard_main-[0-9a-f]+)\)',output)
            if len(matches)!=1:raise RuntimeError('private executable identity missing')
            executable=Path(matches[0])
            if executable.is_symlink() or not executable.is_file() or not executable.resolve().is_relative_to(self.private/'target') or not 0<executable.stat().st_size<=2*1024**3:
                raise RuntimeError('private executable identity bounds')
            digest=binary_digest(executable)
            if phase=='consume':self.private_binary_sha256=digest
            elif digest!=self.private_binary_sha256:raise RuntimeError('private executable changed across restart')

        finally:
            if child.poll() is None:child.kill();child.wait(timeout=2);self.reap_log(child);self.reaped(child)

    def run(self):
        self.start_fixture();self.start_provider();self.offline('prepare');self.bootstrap_coverage();self.start_notifications();self.start_server()
        self.check_coverage();ids=[]
        for account in ('a','b'):
            event={'id':str(uuid.uuid4()),'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                'source':{'type':'query-simulation'},'severity':'error','message':'Standard private consumer '+account,
                'resource':{'kind':'host','id':'host-'+account,'account_id':account}}
            if self.request('/v1/events',method='POST',body=event)[0]!=202:raise RuntimeError('private consumer native admission')
            ids.append(event['id'])
        self.wait(lambda:len(self.events()['events'])==2)
        profile=json.loads((self.out/'shared.json').read_text())
        # Feed identity is the global store, independent of the WAL stream.
        store_id=profile['scope']['store_id']
        directory=self.out/'private-consumer';directory.mkdir(mode=0o700)
        identity=self.pki.private/'private-consumer.pem'
        identity.write_bytes((self.pki.private/'standard/client.pem').read_bytes()+(self.pki.private/'standard/client.key').read_bytes());identity.chmod(0o600)
        BASE.write_json(self.out/'private-consumer.json',{'schema_version':1,'endpoint':f'https://127.0.0.1:{self.server_port}',
            'identity_pem':str(identity),'root_pem':str(self.pki.private/'standard/ca.pem'),'directory':str(directory),
            'consumer':str(uuid.uuid4()),'stream':store_id,'events':ids,
            'notification_endpoint':f'http://127.0.0.1:{self.notifications.server_port}/notify','phase':'consume'})
        self.consume('consume')
        if len(self.notification_rows)!=2 or any(len(v)!=3 or len(set(v))!=1 for v in self.notification_rows.values()):
            raise RuntimeError('private stable notification payload/key through lost reply/429/200')
        feed=json.loads((directory/'original-feed.json').read_text());witness=[]
        for key,rows in sorted(self.notification_rows.items()):
            payload=json.loads(rows[0]);originals=[f for f in feed['findings'] if f['id']==payload['finding']['id']]
            if payload.get('schema_version')!=1 or payload.get('delivery_id')!=key or len(originals)!=1 or originals[0]!=payload['finding']:
                raise RuntimeError('notification canonical original finding binding')
            name='notification-'+hashlib.sha256(key.encode()).hexdigest()+'.json';(directory/name).write_bytes(rows[0])
            witness.append({'delivery_id':key,'payload_file':name,'payload_sha256':hashlib.sha256(rows[0]).hexdigest(),
                            'payload_bytes':len(rows[0]),'attempts':3,'response_sequence':['accepted_reply_lost',429,200]})
        BASE.write_json(directory/'notifications.json',witness)
        self.notification_witness_sha256=hashlib.sha256((directory/'notifications.json').read_bytes()).hexdigest()
        self.stop('server');self.offline('verify');self.offline('restore_scope_stage');self.record('actual_Standard_native_feed_private_atomic_outbox_exact_replay_three_attempt_notifications',event_ids=ids)
        if getattr(self,'restore_mode',False):
            self.consume('inspect');self.offline('restore_scope')
            original_root=self.server_root;restored_root=self.out/'restored-server'
            files=list(original_root.rglob('*'))
            if len(files)>256 or any(p.is_symlink() for p in files) or sum(p.stat().st_size for p in files if p.is_file())>64*1024**2:
                raise RuntimeError('stopped WAL copy bounds')
            shutil.copytree(original_root,restored_root)
            for path in files:
                if path.is_file() and path.read_bytes()!=(restored_root/path.relative_to(original_root)).read_bytes():
                    raise RuntimeError('stopped root copy changed original bytes')
            self.server_root=restored_root
            shutil.copyfile(self.out/'shared.json',self.out/'source-shared.json')
            shutil.copyfile(self.out/'restored-shared.json',self.out/'shared.json')
            receipt=BASE.read_json(self.out/'scoped-restore-receipt.json')
            self.restore_receipt=receipt
            stale=BASE.read_json(self.out/'shared.json');stale['scope']['generation']=receipt['old_generation']
            stale_path=self.out/'stale-restored-shared.json';BASE.write_json(stale_path,stale)
            environment=self.env();environment['SIGNAL_SHARED_CONFIG']=str(stale_path)
            child=self.spawn([str(self.binary)],environment,'denied-restored-old-generation')
            try:
                child.wait(timeout=5);self.reap_log(child);self.reaped(child)
                log=(self.out/'denied-restored-old-generation.log').read_text()
                messages=[json.loads(line).get('fields',{}).get('message') for line in log.splitlines()]
                if not child.returncode or messages.count('shared control authority is stale or denied')!=1 or messages.count('Standard startup resources drained')!=1:
                    raise RuntimeError('old-generation restored Main was not explicitly fenced and drained')
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=2);self.reap_log(child);self.reaped(child)
            self.restored_old_generation_startup_fenced=True
        else:time.sleep(16)
        self.start_server();self.check_coverage();self.consume('resume')
        if self.notification_calls!=6:raise RuntimeError('private restart dispatched historical delivery again')
        if getattr(self,'restore_mode',False):
            restored=self.events()['events']
            if sorted(e['id'] for e in restored)!=sorted(ids):raise RuntimeError('restored original query events')
            event={'id':str(uuid.uuid4()),'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                'source':{'type':'query-simulation'},'severity':'error','message':'fresh restored Standard publication',
                'resource':{'kind':'host','id':'host-a','account_id':'a'}}
            if self.request('/v1/events',method='POST',body=event)[0]!=202:raise RuntimeError('restored fresh native admission')
            self.wait(lambda:len(self.events()['events'])==3)
            self.restored_event_id=event['id'];self.stop('server');self.offline('verify_restored');self.offline('verify','offline-original-source-unchanged')
            time.sleep(16);self.offline('retirement_restored');self.restored_retirement_qualified=True
            self.record('actual_Standard_fresh_destination_generation_original_cursor_restart_and_new_native_publication',event_id=event['id'])
        else:
            self.stop('server');self.offline('verify','offline-verify-after-private-restart')
            self.record('actual_Standard_original_feed_cursor_private_restart_no_historical_redelivery')
        self.private_event_ids=ids
        self.private_feed_sha256=hashlib.sha256((directory/'original-feed.json').read_bytes()).hexdigest()

    def cleanup_all(self):
        try:super().cleanup_all()
        finally:
            if self.notifications is not None:ACCESS.stop_provider(self.notifications,self.notification_thread)

class AuditRun(Run):
    """Actual dedicated receiver; retained protocol proof, no DAC/AWS claim."""
    def __init__(self,*args):
        super().__init__(*args)
        self.audit_mode=True;self.receiver=None;self.receiver_generation=0
        self.audit_append_port=BASE.port();self.audit_health_port=BASE.port()
        self.audit_append_token='synthetic-standard-audit-append'
        self.audit_health_token='synthetic-standard-audit-health'

    def env(self):
        environment=super().env()
        if hasattr(self,'audit_profile'):
            environment.update(SIGNAL_AUDIT_CONFIG=str(self.audit_profile),SIGNAL_AUDIT_TOKEN=self.audit_append_token)
        return environment

    def stop(self,name,kill=False):
        child=getattr(self,name)
        super().stop(name,kill=kill)
        if name=='receiver' and child is not None and not kill and child.returncode!=0:
            raise RuntimeError('independent audit receiver graceful shutdown failed')

    def configure_audit(self):
        self.receipts=self.out/'audit-receipts'
        self.receipts.mkdir(mode=0o700)
        self.outbox=self.out/'audit-outbox'
        state=BASE.read_json(self.outbox/'state')
        if state['schema_version']!=1 or state['acknowledged'] is not None or not uuid.UUID(state['producer_id']).int:
            raise RuntimeError('audit outbox explicit owner enrollment')
        self.audit_producer=state['producer_id']
        materials={}
        for role in ('append','health'):
            ca=self.pki.ca('audit-'+role)
            server=self.pki.leaf(ca,'audit-'+role+'-server','serverAuth')
            client=self.pki.leaf(ca,'audit-'+role+'-client','clientAuth')
            crl=self.pki.crl(ca,'audit-'+role+'-current')
            materials[role]=self.pki.material('audit-'+role+'-server',server,[ca],[crl])
            if role=='append':client_tls=self.pki.material('audit-append-client',client,[ca],[crl])
            else:self.audit_health_context=self.pki.context(ca,client)
        self.receiver_env={k:v for k,v in os.environ.items() if not k.startswith('SIGNAL_')}
        self.receiver_env.update(SIGNAL_STANDARD_AUDIT_APPEND_TOKEN=self.audit_append_token,
                                 SIGNAL_STANDARD_AUDIT_HEALTH_TOKEN=self.audit_health_token)
        self.receiver_config=self.out/'audit-receiver.json'
        BASE.write_json(self.receiver_config,{'schema_version':1,'directory':str(self.receipts),
            'append':{'listen':f'127.0.0.1:{self.audit_append_port}','tls_config':str(materials['append']),'max_connections':4},
            'health':{'listen':f'127.0.0.1:{self.audit_health_port}','tls_config':str(materials['health']),'max_connections':2},
            'producers':[{'producer_id':self.audit_producer,'credential_env':'SIGNAL_STANDARD_AUDIT_APPEND_TOKEN'}],
            'health_credential_env':'SIGNAL_STANDARD_AUDIT_HEALTH_TOKEN','max_bytes':131072,'max_records':64,
            'request_timeout_ms':700,'header_timeout_ms':700,'connection_timeout_ms':1500,'shutdown_timeout_ms':1000})
        self.audit_profile=self.out/'audit.json'
        BASE.write_json(self.audit_profile,{'schema_version':1,'operations':[],
            'configuration_activations':['runtime','rules'],'endpoint':f'https://127.0.0.1:{self.audit_append_port}/v1/audit/records',
            'tls_config':str(client_tls),'outbox_directory':str(self.outbox),'connect_timeout_ms':300})
        child=self.spawn([str(self.binary),'--initialize-audit-receiver','--config',str(self.receiver_config)],
                         self.receiver_env,'audit-receiver-initialize')
        try:
            child.wait(timeout=5)
            if child.returncode:raise RuntimeError('explicit audit receiver initialization')
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=2)
            self.reap_log(child);self.reaped(child)

    def audit_health(self,count):
        if self.receiver.poll() is not None:raise RuntimeError('independent receiver exited')
        status,body=TRANSPORT.absolute_request(self.audit_health_context,self.audit_health_port,
            '/v1/audit/health',self.audit_health_token,timeout=2,method='GET',body=None)
        data=json.loads(body)
        if status!=200 or data['held'] or data['records']!=count:raise RuntimeError('independent receiver health/history')
        return data

    def start_receiver(self,count):
        self.receiver_generation+=1
        self.receiver=self.spawn([str(self.binary),'--audit-receiver','--config',str(self.receiver_config)],
            self.receiver_env,'audit-receiver-'+str(self.receiver_generation))
        def ready():
            try:return bool(self.audit_health(count))
            except (OSError,TimeoutError):return False
        self.wait(ready,seconds=5)

    def run(self):
        journal=module('standard_audit_journal','scripts/check-audit-role-composition.py').journal
        self.start_fixture();self.start_provider();self.offline('prepare');self.bootstrap_coverage()
        self.configure_audit();self.start_receiver(0);self.start_server();self.check_coverage()
        initial=journal(self.receipts/'journal')
        if len(initial)!=2 or [r['record']['action']['configuration'] for r in initial]!=['runtime','rules']:
            raise RuntimeError('activation receipts before Standard readiness')
        self.stop('server');self.audit_health(2)
        if journal(self.receipts/'journal')!=initial:raise RuntimeError('receiver history changed on observability stop')
        control=(self.receipts/'control').read_bytes()
        self.record('actual_Standard_activation_receipts_before_ready_independent_receiver_survives_stop')
        time.sleep(16);self.stop('receiver')
        began=time.monotonic()
        child=self.spawn([str(self.binary)],self.env(),'audit-required-outage')
        try:
            child.wait(timeout=7);self.reap_log(child);self.reaped(child)
            log=(self.out/'audit-required-outage.log').read_text()
            if child.returncode==0 or 'restricted audit is unavailable' not in log or 'Standard startup resources drained' not in log:
                raise RuntimeError('required audit outage did not hold and drain Standard')
            self.audit_failure_seconds=time.monotonic()-began
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=2);self.reap_log(child);self.reaped(child)
        pending=(self.outbox/'pending').read_bytes()
        if not 0<len(pending)<=4096:raise RuntimeError('pending audit byte bound')
        record=json.loads(pending)
        if record['sequence']!=3 or record['action']['configuration']!='runtime':raise RuntimeError('original pending activation')
        (self.out/'audit-original-pending.bin').write_bytes(pending)
        self.record('actual_Standard_required_audit_outage_holds_with_original_pending_receipt')
        self.start_receiver(2);time.sleep(16);self.start_server();self.check_coverage()
        final=journal(self.receipts/'journal')
        if len(final)!=5 or final[:2]!=initial or final[2]['original']!=pending:
            raise RuntimeError('exact original pending audit replay')
        if [r['record']['sequence'] for r in final]!=list(range(1,6)) or any(r['record']['producer_id']!=self.audit_producer or r['record']['actor']!={'kind':'system'} for r in final):
            raise RuntimeError('audit producer/system/sequence contract')
        if [r['record']['action']['configuration'] for r in final]!=['runtime','rules','runtime','runtime','rules']:
            raise RuntimeError('fresh activations after pending replay')
        if final[0]['record']['action']!=final[3]['record']['action'] or final[1]['record']['action']!=final[4]['record']['action']:
            raise RuntimeError('unchanged runtime/rules revision binding')
        if (self.receipts/'control').read_bytes()!=control or (self.outbox/'pending').exists():
            raise RuntimeError('receiver identity or pending confirmation')
        state=BASE.read_json(self.outbox/'state')
        if state['acknowledged']['sequence']!=5:raise RuntimeError('audit original acknowledgement progress')
        self.stop('server');self.audit_health(5);self.stop('receiver');self.offline('verify_audit_empty')
        self.audit_record_ids=[r['record']['record_id'] for r in final]
        self.audit_pending_sha256=hashlib.sha256(pending).hexdigest()
        self.record('actual_Standard_original_audit_replay_fresh_activations_existing_receiver_empty_WAL')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--server',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--scenario',choices=('pipeline','audit','private','restore'),default='pipeline')
    args=parser.parse_args();args.output.mkdir(parents=True,mode=0o700)
    fixture=Path(os.environ['SIGNAL_CONTROL_FIXTURE']);run=({'audit':AuditRun,'private':PrivateRun,'restore':PrivateRun}.get(args.scenario,Run))(args.output.resolve(),args.server.resolve(),fixture.resolve())
    run.restore_mode=args.scenario=='restore'
    report={'schema_version':1,'status':'failed','scope':'actual Standard executable, owned PostgreSQL TLS and persistent S3 protocol simulation; no AWS/ARM64/release proof'}
    try:
        run.run()
        if args.scenario in ('private','restore'):
            report['scope']='Actual native Standard feed, external private SQLite outbox and bounded loopback notification uncertainty/retries; no restore/AWS/ARM64/release claim'
            report.update(status='passed_simulated',scenarios=run.scenarios,binary_sha256=binary_digest(run.binary),child_capacity=3,log_capacity=24,
                          provider_calls=run.provider_calls,event_ids=run.private_event_ids,raw_feed_sha256=run.private_feed_sha256,
                          notification_calls=run.notification_calls,notification_deliveries=len(run.notification_rows),private_original_cursor_restart_qualified=True,populated_scope_restore_stage_qualified=True,
                          notification_witness_sha256=run.notification_witness_sha256,private_binary_sha256=run.private_binary_sha256)
            if args.scenario=='restore':
                report['scope']='Actual fresh compiled-DDL stopped scoped restore, current pinned object custody and private progress, generation fencing, restored native Standard query and new publication; local simulation only'
                report.update(scoped_restore_generation_qualified=True,restored_native_publication_qualified=True,restored_retirement_qualified=run.restored_retirement_qualified,
                              restore_receipt=run.restore_receipt,restored_event_id=run.restored_event_id,
                              old_generation_Main_fenced=run.restored_old_generation_startup_fenced,original_source_checkpoint_unchanged=True)
        elif args.scenario=='audit':
            report['scope']='Actual Standard activation/outage/exact pending replay and actual independent audit receiver over loopback mTLS, with owned PostgreSQL and S3 simulation; excludes pipeline/crash matrix, DAC, AWS, ARM64 and release proof'
            report.update(status='passed_simulated',scenarios=run.scenarios,binary_sha256=binary_digest(run.binary),
                          child_capacity=3,log_capacity=24,provider_calls=run.provider_calls,
                          audit_record_ids=run.audit_record_ids,audit_producer_id=run.audit_producer,
                          original_pending_sha256=run.audit_pending_sha256,required_audit_failure_seconds=run.audit_failure_seconds,
                          independent_receiver_qualified=True,exact_pending_replay_qualified=True,empty_WAL_qualified=True)
        else:report.update(status='passed_simulated',scenarios=run.scenarios,provider_calls=run.provider_calls,
                                producer_credentials_qualified=True,empty_catalog_qualified=True,
                                original_publication_crash_recovery_qualified=True,original_crash_request_id=run.crash_request_id,
                                original_crash_event_id=run.crash_event_id,child_capacity=3,log_capacity=24,
                                unprepared_native_wal_hold_qualified=True,pending_native_event_id=run.pending_event_id,
                                selected_coverage_startup_and_restart_qualified=True,
                                missing_coverage_failure_qualified=True,missing_coverage_failure_seconds=run.missing_coverage_failure_seconds,
                                startup_interruption_qualified=True,startup_interruption_seconds=run.startup_interruption_seconds,
                                late_startup_failure_qualified=True,late_startup_failure_seconds=run.startup_failure_seconds,
                                invalid_cache_failure_qualified=True,invalid_cache_failure_seconds=run.invalid_cache_failure_seconds,
                                startup_denials=['owner-capable-producer','direct-reader-as-producer'],
                                binary_sha256=binary_digest(run.binary))
    finally:
        run.cleanup_all();BASE.write_json(args.output/'report.json',report)
    print('Standard executable process gate passed')
if __name__=='__main__':main()

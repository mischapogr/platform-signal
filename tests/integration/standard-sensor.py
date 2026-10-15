"""Actual Standard sensor baseline; independently signed observer authority is synthetic."""
import base64
import copy
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid

SCENARIOS = (
    'Standard_SENSOR_explicit_zero_checkpoint_idle_without_events',
    'Standard_SENSOR_current_signed_probe_and_causal_overdue_unknown',
    'Standard_SENSOR_fresh_gap_atomic_finding_idle_prefix_retirement',
    'Standard_SENSOR_forged_probe_refused_before_WAL',
    'Standard_SENSOR_SIGKILL_restart_original_scope_bytes_and_replay_unknown',
    'Standard_SENSOR_fresh_post_restart_probe_resumes_current_health',
    'Standard_SENSOR_observed_maintenance_COMMIT_SIGKILL_exact_target_recovery',
    'Standard_SENSOR_native_maintenance_exact_cancel_stale_and_later_divergence',
    'Standard_SENSOR_native_bootstrap_quota_refusal_original_empty_inventory',
    'Standard_SENSOR_late_COMMIT_cancel_deadline_uncertain_and_native_growth_quota',
)

def make(base, util):
    class SensorRun(base):
        sensor_mode = True

        def env(self):
            env = super().env()
            if (self.out/'sensor.json').exists():
                env['SIGNAL_SENSOR_HEALTH_CONFIG'] = str(self.out/'sensor.json')
            return env

        def snapshot(self, label, minimum_revision=None):
            threshold=self.out/'sensor-minimum-revision.json'
            if minimum_revision is None:threshold.unlink(missing_ok=True)
            else:util.write_json(threshold,minimum_revision)
            self.offline('sensor_snapshot_restored' if getattr(self,'sensor_restored',False) else 'sensor_snapshot', 'sensor-snapshot-'+label)
            value = util.read_json(self.out/'sensor-snapshot.json')
            util.write_json(self.out/('sensor-'+label+'.json'), value)
            return value

        def metrics(self):
            status, body = self.request('/metrics')
            if status != 200: raise RuntimeError('sensor metrics HTTP status')
            values = {}
            for line in body.decode().splitlines():
                if not line.startswith('signal_sensor_health_'):continue
                key, value = line.split()
                name=key.removeprefix('signal_sensor_health_')
                if name in values or '{' in key:raise RuntimeError('sensor metric identity/duplicate')
                values[name] = int(value)
            return values

        def metric(self, name):
            value = self.metrics()
            if name not in value:raise RuntimeError('sensor metric missing: '+name)
            return value[name]

        def retired(self):
            value = self.metrics()
            return value.get('pending') == 0 and value.get('operations') == 0

        def openssl(self, *args):
            subprocess.run(['openssl', *map(str,args)], check=True, timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def configure_sensor(self, heartbeat_ms=5000):
            self.sensor_dir = self.out/'sensor'
            self.sensor_dir.mkdir(mode=0o700)
            self.key = self.sensor_dir/'observer.key'
            public = self.sensor_dir/'observer.der'
            self.openssl('genpkey','-algorithm','ED25519','-out',self.key)
            self.openssl('pkey','-in',self.key,'-pubout','-outform','DER','-out',public)
            self.source, self.observer = str(uuid.UUID(int=1)), str(uuid.UUID(int=2))
            self.policy = {'schema_version':1,'rule_id':'fixture.sensor-health','revision':'fixture-v1',
                'heartbeat_ms':heartbeat_ms,'grace_ms':100,'observer_freshness_ms':60000,'max_sources':1,'max_state_bytes':8192,
                'expected':[{'source_id':self.source,'binding':[1]*32,'observer_id':self.observer,
                    'expected_since_ms':time.time_ns()//1_000_000,'require_checkpoint':True}]}
            self.policy_sha = list(hashlib.sha256(json.dumps(self.policy,separators=(',',':')).encode()).digest())
            config = {'schema_version':2,'owner_generation':str(uuid.UUID(int=3)),'cadence_ms':50,
                'shared':{'state_key':'standard-sensor','bootstrap_checkpoint':0,'recovery':{
                    'files':128,'object_bytes':67108864,'decoded_bytes':67108864,'scanned_rows':4096,'result_bytes':1048576}},
                'detector':{'schema_version':1,'policy':self.policy,'observer_keys':[{'schema_version':1,
                    'observer_id':self.observer,'public_key':list(public.read_bytes()[-32:])}],
                    'source_scopes':[{'schema_version':1,'source_id':self.source,'event_scope':{
                        'schema_version':1,'source':'synthetic-sensor','account':'a','resource':'host-a'}}],
                    'title':'Fixture independent collection gap','severity':'high','max_proofs':3,'max_event_bytes':16384,
                    'max_state_bytes':262144,'max_record_bytes':1048576,'max_outputs':4,'max_output_bytes':65536,
                    'max_history_assessments':4,'max_history_bytes':65536,'history_retention_ms':1500}}
            util.write_json(self.out/'sensor.json',config)

        def probe(self, sequence, heartbeat=None, forged=False):
            observed = time.time_ns()//1_000_000
            heartbeat = observed if heartbeat is None else heartbeat
            payload = json.dumps({'schema_version':1,'policy_sha256':self.policy_sha,'observation':{
                'schema_version':1,'source_id':self.source,'binding':[1]*32,'observer_id':self.observer,
                'sequence':sequence,'observed_at_ms':observed,'health':'healthy','heartbeat_at_ms':heartbeat,
                'checkpoint':sequence}},separators=(',',':')).encode()
            data, signature = self.sensor_dir/'signed.bin', self.sensor_dir/'signature.bin'
            data.write_bytes(b'platform-signal/sensor-health-observer/v1\0'+payload)
            self.openssl('pkeyutl','-sign','-rawin','-inkey',self.key,'-in',data,'-out',signature)
            envelope = {'schema_version':1,'observer_id':self.observer,'payload_base64':base64.b64encode(payload).decode(),
                        'signature_base64':base64.b64encode(bytes(64) if forged else signature.read_bytes()).decode()}
            stamp = datetime.datetime.fromtimestamp(observed/1000,datetime.timezone.utc).isoformat().replace('+00:00','Z')
            return {'id':str(uuid.uuid4()),'timestamp':stamp,'observed_at':stamp,'source':{'type':'synthetic-sensor'},
                'resource':{'kind':'host','id':'host-a','account_id':'a'},'attributes':{
                    'signal.sensor_health.observation':json.dumps(envelope)}}, heartbeat

        def send(self, event, checkpoint):
            status, body = self.request('/v1/events',method='POST',body=event)
            if status != 202 or json.loads(body)['event_ids'] != [event['id']]:
                raise RuntimeError('sensor canonical admission status')
            self.wait(lambda:self.checkpoint()==checkpoint)

        def bootstrap_quota_refusal(self):
            self.offline('sensor_quota_limit')
            child=None
            try:
                child=self.spawn([str(self.binary)],self.env(),'sensor-quota-refused')
                child.wait(timeout=7)
                if child.returncode==0 or 'shared control capacity exhausted' not in (self.out/'sensor-quota-refused.log').read_text():
                    raise RuntimeError('sensor bootstrap quota refused for unexpected reason')
                if self.checkpoint()!=0:raise RuntimeError('sensor bootstrap quota refusal advanced WAL')
            finally:
                if child is not None:
                    if child.poll() is None:child.kill();child.wait(timeout=2)
                    self.reap_log(child);self.reaped(child)
                self.offline('sensor_quota_restore')
            time.sleep(16)  # The actual refused startup owner lease must expire.
            self.record(SCENARIOS[8])

        def maintenance_commit_crash(self):
            environment={k:v for k,v in os.environ.items() if not k.startswith('SIGNAL_')}
            environment.update(SIGNAL_CONTROL_FIXTURE=str(self.control),SIGNAL_STANDARD_ROOT=str(self.out),
                SIGNAL_STANDARD_BACKEND=self.fixture_id,SIGNAL_STANDARD_PHASE='sensor_maintenance_commit',
                SIGNAL_STANDARD_SENSOR='true')
            child=self.spawn([str(self.offline_binary),'standard_offline_fixture','--ignored','--exact','--nocapture'],
                             environment,'sensor-maintenance-commit')
            try:
                self.wait(lambda:(self.out/'sensor-maintenance-lock-ready').is_file(),seconds=5)
                self.wait(lambda:(self.out/'sensor-maintenance-commit-observed').is_file(),seconds=5)
                if self.server.poll() is not None or self.checkpoint()!=2:
                    raise RuntimeError('sensor maintenance COMMIT observation lost native caller or advanced WAL')
                self.stop('server',kill=True)
                (self.out/'sensor-maintenance-caller-killed').write_bytes(b'killed')
                child.wait(timeout=15)
                if child.returncode:raise RuntimeError('sensor maintenance original COMMIT did not persist')
                self.reap_log(child);self.reaped(child)
                marker='phase: Standard-SENSOR-observed-maintenance-COMMIT-SIGKILL-original-target-bytes-head-checkpoint-findings-quota-qualified'
                if (self.out/'sensor-maintenance-commit.log').read_text().splitlines().count(marker)!=1:
                    raise RuntimeError('sensor maintenance COMMIT qualification marker missing')
                committed=util.read_json(self.out/'sensor-maintenance-committed.json')
                target=(self.out/'sensor-maintenance-committed.bin').read_bytes()
                if not committed['observed_commit'] or hashlib.sha256(target).hexdigest()!=committed['target_sha256']:
                    raise RuntimeError('sensor maintenance original committed target binding mismatch')
                for label in ('late-cancelled','late-deadline','growth-quota'):
                    if util.read_json(self.out/('sensor-maintenance-'+label+'.json'))['status']!='passed_simulated':
                        raise RuntimeError('sensor native maintenance failure evidence missing')
                self.record(SCENARIOS[9])
                self.record(SCENARIOS[6])
                return committed
            finally:
                if child.poll() is None:
                    child.kill();child.wait(timeout=2);self.reap_log(child);self.reaped(child)

        def run(self):
            self.start_fixture(); self.start_provider(); self.offline('prepare'); self.bootstrap_coverage()
            self.configure_sensor(); self.bootstrap_quota_refusal(); self.start_server()
            initial = self.snapshot('initial')
            def record(value):return value['state']['metadata']['sensor']['snapshot']['record']
            idle = self.snapshot('idle-zero',record(initial)['revision']+1)
            if (initial['partition']['head'] is not None or initial['partition']['checkpoint'] != 0
                or initial['commits'] != 0 or initial['findings'] != [] or self.checkpoint() != 0
                or idle['partition']['checkpoint'] != 0 or idle['commits'] != 0
                or record(idle)['revision'] <= record(initial)['revision']
                or self.metric('indeterminate') != 1 or self.metric('history_assessments') < 1
                or initial['state_keys'] != ['standard-sensor']):
                raise RuntimeError('sensor initial idle state fabricated events or lacked persisted unknown cadence')
            self.record(SCENARIOS[0])
            first, heartbeat = self.probe(1)
            self.send(first,1); self.wait(lambda:self.metric('coverage_gap')==0)
            self.wait(lambda:self.metric('indeterminate')==1,seconds=7)
            overdue = self.snapshot('causal-overdue')
            if overdue['findings'] or self.checkpoint()!=1:raise RuntimeError('old pre-deadline observation fabricated a gap')
            self.record(SCENARIOS[1])
            gap, _ = self.probe(2,heartbeat)
            self.send(gap,2); self.wait(self.retired)
            published = self.snapshot('gap-retired')
            after = self.snapshot('idle-gap',record(published)['revision']+1)
            if (len(published['findings'])!=1 or record(published)['outbox']!=[]
                or published['partition']['checkpoint']!=2 or after['partition']['head']!=published['partition']['head']
                or after['partition']['checkpoint']!=2 or published['commits']!=2
                or record(after)['revision']<=record(published)['revision']):
                raise RuntimeError('sensor atomic finding or idle retirement/head/checkpoint mismatch')
            self.sensor_original_bytes = published['finding_bytes']
            if 'signal.scope.v1' not in published['findings'][0]['attributes']:raise RuntimeError('sensor original finding lacks native scope')
            self.record(SCENARIOS[2])
            bad, _ = self.probe(3,heartbeat,forged=True)
            if self.request('/v1/events',method='POST',body=bad)[0]!=422 or self.checkpoint()!=2:
                raise RuntimeError('forged sensor validation status or WAL checkpoint mismatch')
            self.record(SCENARIOS[3])
            util.write_json(self.out/'sensor-canonical-events.json',self.events()['events'])
            committed=self.maintenance_commit_crash(); time.sleep(16); self.start_server()
            self.snapshot('restart-idle-before-replay',committed['target_revision']+1)
            self.offline('sensor_maintenance_diverged')
            self.record(SCENARIOS[7])
            self.send(copy.deepcopy(gap),3)
            recovered = self.snapshot('recovered')
            if (self.metric('indeterminate')!=1 or recovered['finding_bytes']!=self.sensor_original_bytes
                or recovered['state']['canonical_sequences'].get(gap['id'])!=2
                or record(recovered)['revision']<committed['target_revision']):
                raise RuntimeError('sensor restart/replay renewed authority or rewrote original provenance')
            self.record(SCENARIOS[4])
            fresh, _ = self.probe(3)
            self.send(fresh,4); self.wait(lambda:self.metric('coverage_gap')==0)
            final = self.snapshot('fresh')
            if final['finding_bytes']!=self.sensor_original_bytes:raise RuntimeError('sensor fresh source report rewrote old findings')
            events=self.events()['events']
            self.sensor_events=[first['id'],gap['id'],fresh['id']]
            if {e['id'] for e in events}!=set(self.sensor_events):raise RuntimeError('sensor canonical query originals missing')
            self.sensor_checkpoint=self.checkpoint()
            self.sensor_finding_sha256=hashlib.sha256(bytes.fromhex(self.sensor_original_bytes[0])).hexdigest()
            self.record(SCENARIOS[5]); self.stop('server')
    return SensorRun

MIXED_SCENARIOS = (
    'Standard_SENSOR_WINDOW_independent_zero_checkpoint_states',
    'Standard_SENSOR_WINDOW_sensor_gap_preserves_unsealed_attempts',
    'Standard_SENSOR_WINDOW_watermark_seals_original_attempts_preserves_sensor_finding',
    'Standard_SENSOR_WINDOW_retries_preserve_original_bodies_and_canonical_positions',
    'Standard_SENSOR_WINDOW_SIGKILL_restart_both_states_unknown_sensor_authority',
)

def make_mixed(sensor, window, util):
    class MixedSensorRun(sensor, window):
        def run(self):
            self.start_fixture();self.start_provider();self.offline('prepare');self.bootstrap_coverage()
            # Mixed publications persist two detector states plus history. Give the
            # synthetic heartbeat a five-second interval so it can remain current
            # through the actual SQL/object commit, then await its causal expiry.
            self.configure_window();self.configure_sensor(heartbeat_ms=5000)
            try:
                self.start_server()
                initial=self.snapshot('mixed-initial')
                if initial['state_keys']!=['standard-sensor'] or initial['commits']!=0:
                    raise RuntimeError('mixed explicit initialization fabricated a commit or omitted a state')
                payload=self.host_evidence.evidence();self.host_evidence.publish(payload)
                if self.readiness()[1]['stage']!='detections_active':raise RuntimeError('mixed signed detection inventory unavailable')
                end=datetime.datetime.fromisoformat(payload['interval']['end'].replace('Z','+00:00'))
                at=(end-datetime.timedelta(seconds=5)).isoformat().replace('+00:00','Z')
                attempts=[{'id':str(uuid.uuid4()),'timestamp':at,'observed_at':at,
                    'source':{'type':'query-simulation','name':'fixture-auth'},
                    'resource':{'kind':'host','id':'host-a','account_id':'a'},'message':'Mixed detector fixture',
                    'attributes':{'authentication':{'identity_authority':'fixture','principal_id':'fixture-user',
                        'target_id':'fixture-target','outcome':'failure'},
                        'producer':{'boot_id':'fixture-boot','sequence':n}}} for n in (1,2)]
                for checkpoint,event in enumerate(attempts,1):self.send(event,checkpoint)
                initialized=self.snapshot('mixed-initialized')
                if initialized['state_keys']!=['standard-sensor','standard-window']:
                    raise RuntimeError('mixed first attempts did not persist both independent states')
                self.record(MIXED_SCENARIOS[0])
                first,heartbeat=self.probe(1);self.send(first,3)
                self.wait(lambda:self.metric('coverage_gap')==0)
                self.wait(lambda:self.metric('indeterminate')==1,seconds=7)
                gap,_=self.probe(2,heartbeat);self.send(gap,4);self.wait(self.retired)
                published=self.snapshot('mixed-gap')
                def bodies(value):return {f['id']:body for f,body in zip(value['findings'],value['finding_bytes'])}
                sensor_findings=[f for f in published['findings'] if f['rule_id']=='fixture.sensor-health']
                if len(sensor_findings)!=1 or any(f['rule_id']=='fixture.auth-window' for f in published['findings']):
                    raise RuntimeError('mixed sensor input fabricated WINDOW attempt or lost sensor finding')
                original_sensor=bodies(published)[sensor_findings[0]['id']]
                self.record(MIXED_SCENARIOS[1])
                later=(end+datetime.timedelta(seconds=15)).isoformat().replace('+00:00','Z')
                payload['interval']['end']=later;payload['coverage_record']['coverage_end']=later
                payload['coverage_record']['last_verified_at']=later;payload['coverage_record']['provenance']['observed_at']=later
                self.host_evidence.publish(payload);self.send(attempts[0],5)
                sealed=self.snapshot('mixed-sealed')
                matches=[f for f in sealed['findings'] if f['rule_id']=='fixture.auth-window']
                if (len(matches)!=1 or matches[0]['event_ids']!=[e['id'] for e in attempts]
                    or bodies(sealed).get(sensor_findings[0]['id'])!=original_sensor
                    or any(sealed['states'][key]==published['states'][key] for key in initialized['state_keys'])):
                    raise RuntimeError('mixed publication lost independent state progress or original provenance')
                def check_positions(value,checkpoint):
                    expected={'standard-window':{e['id']:n for n,e in enumerate(attempts,1)},
                              'standard-sensor':{first['id']:3,gap['id']:4}}
                    for key,positions in expected.items():
                        state=value['states'][key]
                        if state['checkpoint']!=checkpoint or state['canonical_sequences']!=positions:
                            raise RuntimeError('mixed independent state checkpoint or original canonical positions changed')
                check_positions(sealed,5)
                original=bodies(sealed)
                self.record(MIXED_SCENARIOS[2])
                self.send(gap,6);self.send(attempts[0],7)
                retried=self.snapshot('mixed-retried')
                check_positions(retried,7)
                if (bodies(retried)!=original or retried['state']['canonical_sequences'].get(gap['id'])!=4):
                    raise RuntimeError('mixed retry changed original finding bytes or sensor canonical position')
                self.record(MIXED_SCENARIOS[3])
                self.stop('server',kill=True);time.sleep(16)
                self.host_evidence.publish(payload);self.start_server();self.send(gap,8);self.send(attempts[1],9)
                recovered=self.snapshot('mixed-recovered')
                check_positions(recovered,9)
                self.sensor_events=[e['id'] for e in attempts]+[first['id'],gap['id']]
                if (bodies(recovered)!=original or self.metric('indeterminate')!=1
                    or recovered['state_keys']!=initialized['state_keys']
                    or {e['id'] for e in self.events()['events']}!=set(self.sensor_events)):
                    raise RuntimeError('mixed restart renewed sensor authority or changed original findings/events')
                self.sensor_checkpoint=self.checkpoint()
                self.sensor_finding_sha256=hashlib.sha256(bytes.fromhex(original_sensor)).hexdigest()
                self.record(MIXED_SCENARIOS[4]);self.stop('server')
            finally:self.host_evidence.close()
    return MixedSensorRun


RESTORE_SCENARIOS = (
    'Standard_SENSOR_native_atomic_pending_output_preserved_at_stop',
    'Standard_SENSOR_fresh_trusted_restore_owner_rebind_original_logical_identity',
    'Standard_SENSOR_restored_Main_original_finding_retirement_and_unknown_coverage',
    'Standard_SENSOR_restored_replay_unknown_original_canonical_and_fresh_health',
)

def make_restore(sensor, util):
    class RestoreSensorRun(sensor):
        def run(self):
            self.start_fixture();self.start_provider();self.offline('prepare');self.bootstrap_coverage()
            self.configure_sensor();self.start_server()
            first,heartbeat=self.probe(1);self.send(first,1)
            self.wait(lambda:self.metric('coverage_gap')==0)
            self.wait(lambda:self.metric('indeterminate')==1,seconds=7)
            # The fixture refuses only a pending-outbox retirement. Empty idle
            # cadence and the actual native atomic event/state/finding COMMIT
            # remain authorized; the original pending output stays durable.
            self.offline('sensor_hold_retirement')
            gap,_=self.probe(2,heartbeat);self.send(gap,2)
            pending=self.snapshot('restore-pending')
            record=pending['state']['metadata']['sensor']['snapshot']['record']
            if len(record['outbox'])!=1 or len(pending['findings'])!=1:
                raise RuntimeError('native publication did not retain original pending known output')
            self.sensor_original_bytes=pending['finding_bytes']
            self.record(RESTORE_SCENARIOS[0]);self.stop('server',kill=True)
            self.offline('sensor_restore')
            receipt=util.read_json(self.out/'sensor-restore-receipt.json')
            old=util.read_json(self.out/'shared.json');fresh=util.read_json(self.out/'restored-shared.json')
            if (fresh['scope_generation']!=old['scope_generation']
                or fresh['scope']['generation']==old['scope']['generation']
                or receipt['pending_outputs']!=1 or receipt['checkpoint']!=2):
                raise RuntimeError('restore changed logical scope or lost original pending output')
            restored=self.out/'restored-server';files=list(self.server_root.rglob('*'))
            if len(files)>256 or any(p.is_symlink() for p in files) or sum(p.stat().st_size for p in files if p.is_file())>64*1024**2:
                raise RuntimeError('sensor stopped WAL copy bounds')
            shutil.copytree(self.server_root,restored)
            for path in files:
                if path.is_file() and path.read_bytes()!=(restored/path.relative_to(self.server_root)).read_bytes():
                    raise RuntimeError('sensor stopped WAL copy changed original bytes')
            self.server_root=restored
            shutil.copyfile(self.out/'shared.json',self.out/'source-shared.json')
            shutil.copyfile(self.out/'restored-shared.json',self.out/'shared.json')
            self.sensor_restored=True;self.restore_receipt=receipt
            self.record(RESTORE_SCENARIOS[1]);self.start_server()
            self.wait(self.retired)
            recovered=self.snapshot('restored-retired')
            if (self.metric('indeterminate')!=1 or recovered['finding_bytes']!=self.sensor_original_bytes
                or recovered['state']['scope_generation']!=old['scope_generation']
                or recovered['state']['metadata']['scope']!=fresh['scope']
                or recovered['partition']['checkpoint']!=2):
                raise RuntimeError('restored native recovery changed original output or renewed authority')
            self.record(RESTORE_SCENARIOS[2])
            self.send(copy.deepcopy(gap),3)
            replay=self.snapshot('restored-replay')
            if (self.metric('indeterminate')!=1 or replay['finding_bytes']!=self.sensor_original_bytes
                or replay['state']['canonical_sequences'].get(gap['id'])!=2):
                raise RuntimeError('restored replay changed canonical evidence or renewed authority')
            report,_=self.probe(3);self.send(report,4)
            self.wait(lambda:self.metric('coverage_gap')==0)
            final=self.snapshot('restored-fresh')
            if final['finding_bytes']!=self.sensor_original_bytes:
                raise RuntimeError('restored fresh input rewrote historical finding')
            self.sensor_events=[first['id'],gap['id'],report['id']]
            if {e['id'] for e in self.events()['events']}!=set(self.sensor_events):
                raise RuntimeError('restored canonical originals unavailable')
            self.sensor_checkpoint=self.checkpoint()
            self.sensor_finding_sha256=hashlib.sha256(bytes.fromhex(self.sensor_original_bytes[0])).hexdigest()
            self.record(RESTORE_SCENARIOS[3]);self.stop('server')
    return RestoreSensorRun

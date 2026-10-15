"""Actual Small Main WINDOW journal/outbox crash boundaries; synthetic host authority."""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import sqlite3
import time
import uuid


def exercise(root, policy_path, policy, evidence, publish, assess, checkpoint, start, stop, request, hold_request):
    began = time.monotonic()
    checks = []
    repo=Path(__file__).resolve().parents[1]
    sources=[repo/'Cargo.toml',repo/'Cargo.lock',repo/'scripts/check-onboarding-native.py',
        repo/'scripts/onboarding-native-fixture.py',repo/'scripts/window-native-fixture.py',repo/'tests/integration/access-server-process.py',
        repo/'scripts/check-object-query.py']
    for component in ['apps/signal-server','crates/signal-rules','crates/signal-findings','crates/signal-buffer','crates/signal-protocol','crates/signal-ingest','crates/signal-coverage']:
        sources.extend([repo/component/'Cargo.toml',*(repo/component/'src').rglob('*.rs')])
    hashes={str(p.relative_to(repo)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    binary=Path(sys.argv[1]).resolve()
    with binary.open('rb') as stream:binary_sha256=hashlib.file_digest(stream,'sha256').hexdigest()
    held_request=None
    original_policy = policy_path.read_bytes()
    directory = root / 'window'
    directory.mkdir(mode=0o700)
    database = directory / 'state.sqlite'
    config = root / 'window.json'
    rule = 'fixture.auth-window'
    document = copy.deepcopy(policy)
    detection = copy.deepcopy(document['detections'][0]);detection['id'] = rule
    document['detections'].append(detection)
    policy_path.write_text(json.dumps(document))
    policy_window = {'schema_version': 1, 'partition': (root/'wal/identity').read_text(),
        'rule_id': rule, 'revision': 'fixture-v1', 'title': 'Small native fixture window',
        'severity': 'high', 'threshold': 2, 'window_ms': 60000, 'lateness_ms': 10000, 'ttl_ms': 70000,
        'max_keys': 4, 'max_attempts_per_key': 16, 'max_attempts': 32, 'max_outputs': 32,
        'max_state_bytes': 65536, 'max_history_assessments': 32, 'max_history_bytes': 262144,
        'history_retention_ms': 60000}
    config.write_text(json.dumps({'schema_version': 1, 'database': str(database), 'policy': policy_window}))
    overrides = {'SIGNAL_ONBOARDING_CONFIG': str(policy_path), 'SIGNAL_WINDOW_CONFIG': str(config)}
    def stamp(at):return at.isoformat().replace('+00:00','Z')
    def wait(predicate):
        end = time.monotonic()+5
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.005)
        raise RuntimeError('Small WINDOW bounded milestone deadline')
    def findings(token='global'):
        code,rows,_=request('GET','/v1/findings?limit=100',token=token)
        assert code==200
        return rows['findings']
    def snapshot_bytes():
        with sqlite3.connect(f'file:{database}?mode=ro',uri=True,timeout=.05) as db:
            row=db.execute('SELECT checkpoint,substr(payload,1,131073) FROM window_snapshot WHERE singleton=1').fetchone()
        if row is None:return None
        assert len(row[1])<=131072
        value=json.loads(row[1]);assert row[0]==value['checkpoint']
        return row[1]
    def snapshot():
        raw=snapshot_bytes()
        return json.loads(raw) if raw is not None else None
    def raw_findings():
        with (root/'findings/findings.journal').open('rb') as stream:data=stream.read(1048577)
        assert len(data)<=1048576
        return data
    def event(at,sequence,principal='fixture-user'):
        return {'id':str(uuid.uuid4()),'timestamp':stamp(at),'observed_at':stamp(at),
            'source':{'type':'synthetic','name':'fixture-auth'},'message':'Small WINDOW native fixture',
            'resource':{'kind':'host','id':'resource-a','account_id':'a'},
            'attributes':{'authentication':{'identity_authority':'fixture','principal_id':principal,
                'target_id':'fixture-target','outcome':'failure'},'producer':{'boot_id':'fixture-boot','sequence':sequence}}}
    def send(value):
        code,result,_=request('POST','/v1/events/batch',{'events':[value]},'write-a')
        assert code==202 and result['event_ids']==[value['id']]
    def advance(payload):
        # A signed, continuous fixture interval advances; event fields cannot seal.
        end=dt.datetime.fromisoformat(payload['interval']['end'].replace('Z','+00:00'))+dt.timedelta(seconds=15)
        value=copy.deepcopy(payload);value['interval']['end']=stamp(end)
        value['coverage_record']['coverage_end']=stamp(end)
        value['coverage_record']['last_verified_at']=stamp(end)
        value['coverage_record']['provenance']['observed_at']=stamp(end)
        return value
    try:
        baseline=checkpoint()
        start(overrides)
        payload=evidence();publish(payload)
        assert assess()[1]['stage']=='detections_active'
        end=dt.datetime.fromisoformat(payload['interval']['end'].replace('Z','+00:00'))
        attempts=[event(end-dt.timedelta(seconds=5),n) for n in (1,2)]
        for offset,value in enumerate(attempts,1):
            send(value);wait(lambda:checkpoint()==baseline+offset)
        assert not [f for f in findings() if f['rule_id']==rule]
        retained=snapshot()
        assert retained['checkpoint']==baseline+2 and not retained['findings']
        assert {a['event_id'] for a in retained['state']['attempts']}=={e['id'] for e in attempts}
        checks.append('same-time_split_batches_remain_unsealed_until_signed_source_watermark')
        rows=findings();original=raw_findings();stop()
        # Existing stateless repeats fit; only the new WINDOW finding exceeds quota.
        start({**overrides,'SIGNAL_FINDINGS_MAX_FINDINGS':str(len(rows)),'SIGNAL_REQUEST_TIMEOUT_MS':'5000'})
        payload=advance(payload);publish(payload)
        held_request=hold_request()
        send(attempts[0])
        wait(lambda:(snapshot() or {}).get('checkpoint')==baseline+3)
        pending_wire=snapshot_bytes();pending=json.loads(pending_wire)
        assert checkpoint()==baseline+2 and pending['findings']
        assert len({f['id'] for f in pending['findings']})==1
        pending_body=copy.deepcopy(pending['findings'][0])
        assert pending_body['event_ids']==[e['id'] for e in attempts]
        assert raw_findings()==original
        (root/'window-pending-outbox.bin').write_bytes(pending_wire)
        (root/'window-pending-outbox.json').write_text(json.dumps(pending))
        stop(kill=True)
        held_request.close();held_request=None
        assert snapshot_bytes()==pending_wire and checkpoint()==baseline+2
        checks.append('SIGKILL_after_atomic_outbox_commit_before_finding_publication_preserves_original_pending_bytes_and_unacked_WAL')
        publish(payload);start(overrides)
        wait(lambda:checkpoint()==baseline+3)
        matches=[f for f in findings() if f['rule_id']==rule]
        assert len(matches)==1
        published=copy.deepcopy(matches[0]);scope=published['attributes'].pop('signal.scope.v1')
        assert published==pending_body and scope['source']=='synthetic' and scope['account']=='a' and scope['resource']=='resource-a'
        assert matches[0] in findings('read-a')
        assert request('GET','/v1/findings?limit=100',token='read-b')[0]==403
        assert raw_findings().startswith(original) and not snapshot()['findings']
        assert not snapshot()['state']['outputs']
        original=raw_findings();stop(kill=True)
        publish(payload);start(overrides)
        assert raw_findings()==original and [f for f in findings() if f['rule_id']==rule]==matches
        checks.append('restart_publishes_original_scoped_outbox_once_then_retires_outputs_and_preserves_finding_bytes_on_second_SIGKILL')
        # A real SQLite writer holds the journal before commit. Observe the owned
        # physical operation and persisted stateless finding before killing Main.
        blocked=event(dt.datetime.fromisoformat(payload['interval']['end'].replace('Z','+00:00'))-dt.timedelta(seconds=5),3,'uncommitted-user')
        with sqlite3.connect(database,timeout=.05) as db:
            db.execute('BEGIN IMMEDIATE')
            send(blocked)
            def physical_write_held():
                present=any(f['event_ids']==[blocked['id']] for f in findings())
                code,metrics,_=request('GET','/metrics',token='global')
                return present and code==200 and 'signal_window_operations 1\n' in metrics
            wait(physical_write_held)
            assert checkpoint()==baseline+3 and snapshot()['checkpoint']==baseline+3
            stop(kill=True)
            db.rollback()
        checks.append('SIGKILL_with_real_SQLite_contention_before_atomic_commit_preserves_original_journal_and_WAL_checkpoint')
        publish(payload);start(overrides)
        wait(lambda:checkpoint()==baseline+4)
        recovered=snapshot()
        assert blocked['id'] not in {a['event_id'] for a in recovered['state']['attempts']}
        assert recovered['state']['degraded_until'] is not None
        assert [f for f in findings() if f['rule_id']==rule]==matches
        assert raw_findings().startswith(original)
        stop()
        checks.append('uncommitted_retained_event_never_gains_fresh_native_authority_after_restart')
        assert all(hashlib.sha256((repo/p).read_bytes()).hexdigest()==value for p,value in hashes.items())
        with binary.open('rb') as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==binary_sha256
        result={'binary_sha256':binary_sha256,'source_hashes':hashes,'child_capacity':2,'log_capacity':24,'schema_version':1,'status':'passed_simulated','scope':'Actual Small Main native TLS provider, signed synthetic host coverage, SQLite journal/outbox, findings and WAL. No AWS/physical-source/release proof.',
            'passed':len(checks),'checks':checks,'elapsed_seconds':time.monotonic()-began,
            'checkpoint':checkpoint(),'baseline_checkpoint':baseline,'event_ids':[e['id'] for e in attempts],
            'finding_id':matches[0]['id'],'pending_outbox_sha256':hashlib.sha256(pending_wire).hexdigest(),
            'final_findings_sha256':hashlib.sha256(raw_findings()).hexdigest()}
        (root/'window-native-report.json').write_text(json.dumps(result,indent=2)+'\n')
    finally:
        if held_request is not None:held_request.close()
        try:stop()
        finally:policy_path.write_bytes(original_policy)

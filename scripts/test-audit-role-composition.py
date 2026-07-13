#!/usr/bin/env python3
"""Focused health-oracle, journal, lifecycle and owned-network regressions."""
import ast
import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

spec=importlib.util.spec_from_file_location('composition',pathlib.Path(__file__).with_name('check-audit-role-composition.py'))
composition=importlib.util.module_from_spec(spec);spec.loader.exec_module(composition)

def actor_namespace():
    tree=ast.parse(composition.ACTOR);tree.body.pop()  # Exclude executable dispatcher.
    value={'__name__':'fixture_actor'}
    with patch.object(sys,'argv',['/actor.py','command','unused']):exec(compile(tree,'actor-fixture','exec'),value)
    return value

class RoleTests(unittest.TestCase):
    def setUp(self):
        self.actor=actor_namespace()
        self.health={k:0 for k in self.actor['FIELDS']}
        self.health.update(schema_version=1,held=False,record_capacity=64,byte_capacity=131072,physical_capacity=1,append_http_capacity=1)
        self.headers={'content-type':'application/json','cache-control':'no-store'}
        self.actor['context']=Mock(return_value=None)
    def observed(self,value=None,status=200,headers=None,raw=None):
        self.actor['request']=Mock(return_value=(status,raw if raw is not None else json.dumps(self.health if value is None else value).encode(),self.headers if headers is None else headers))
        return self.actor['health']({'token':'private'})
    def test_valid_capacity_observation_and_held_status(self):
        self.assertEqual(self.observed(),self.health)
        value=dict(self.health,held=True);self.assertEqual(self.observed(value,503),value)
    def test_bool_float_negative_and_overflow_are_not_integers(self):
        for field,value in [('schema_version',True),('records',True),('bytes',1.0),('physical_rejected',-1),('rejected',2**64),('held',0)]:
            with self.subTest(field=field):
                body=dict(self.health);body[field]=value
                with self.assertRaises(RuntimeError):self.observed(body)
    def test_capacity_depth_and_status_bounds(self):
        for field,value in [('record_capacity',0),('record_capacity',16385),('byte_capacity',4167),('byte_capacity',67108865),('records',65),('bytes',131073),('physical_capacity',2),('physical_depth',2),('append_http_capacity',0),('append_http_depth',2)]:
            with self.subTest(field=field):
                body=dict(self.health);body[field]=value
                with self.assertRaises(RuntimeError):self.observed(body)
        for body,status in [(self.health,503),(dict(self.health,held=True),200),(self.health,500)]:
            with self.assertRaises(RuntimeError):self.observed(body,status)
    def test_headers_duplicate_contenttype_cache_and_length(self):
        for key,value in [('content-type',None),('cache-control',None),('content-type','application/json; charset=utf-8'),('cache-control','public'),('content-length','1025'),('content-length',None)]:
            h=dict(self.headers);h[key]=value
            with self.assertRaises(RuntimeError):self.observed(headers=h)
    def test_duplicate_unknown_and_missing_json_fields(self):
        raw=json.dumps(self.health).encode();raw=raw[:-1]+b',"schema_version":1}'
        with self.assertRaises(ValueError):self.observed(raw=raw)
        body=dict(self.health,extra=1)
        with self.assertRaises(RuntimeError):self.observed(body)
        body=dict(self.health);del body['held']
        with self.assertRaises(RuntimeError):self.observed(body)
    def test_health_owner_clock_generation_and_failed_probe_nonrenewal(self):
        prior={'monotonic_ns':50,'observations':2,'last_good_receipt_ns':40}
        value={'monotonic_ns':101,'observations':3,'last_good_receipt_ns':40,'status':'unavailable'}
        oracle=self.actor['fresh_observation'];self.assertTrue(oracle(value,prior,100,'unavailable'))
        for field,bad in [('monotonic_ns',100),('observations',2),('last_good_receipt_ns',102)]:
            with self.subTest(field=field):self.assertFalse(oracle(dict(value,**{field:bad}),prior,100,'unavailable'))
        self.assertFalse(oracle(value,{},100,'unavailable'))
        observed=dict(value,status='observed',records=7,held=False,last_good_receipt_ns=101)
        self.assertTrue(oracle(observed,prior,100,'7'));self.assertFalse(oracle(observed,prior,100,'8'))
    def test_owned_address_cache_keeps_tls_host_and_skips_outage_dns(self):
        connection=Mock();response=Mock(status=200);response.read.return_value=b'{}';response.getheaders.return_value=[];connection.getresponse.return_value=response
        with patch.object(self.actor['http'].client,'HTTPSConnection',return_value=connection) as https,patch.object(self.actor['socket'],'gethostbyname',return_value='192.0.2.1') as resolve,patch.object(self.actor['socket'],'create_connection') as connect:
            self.actor['request'](None,'receiver',8082,'/health')
            self.actor['request'](None,'receiver',8082,'/health')
            self.assertEqual(resolve.call_count,1);self.assertEqual(https.call_args.args,('receiver',8082))
            connection._create_connection(('receiver',8082),2);connect.assert_called_once_with(('192.0.2.1',8082),2,None)
    def test_retire_actual_child_group_before_reap(self):
        child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)'],start_new_session=True)
        with patch.object(self.actor['os'],'killpg',wraps=self.actor['os'].killpg) as kill:
            code=self.actor['stop'](child,True)
        self.assertEqual(code,-9);self.assertGreaterEqual(kill.call_count,1)
    def test_already_reaped_child_never_signalled(self):
        child=subprocess.Popen([sys.executable,'-c','pass'],start_new_session=True);child.wait(timeout=2)
        with patch.object(self.actor['os'],'killpg') as kill:self.actor['stop'](child)
        kill.assert_not_called()
    def test_unknown_child_ownership_never_signalled(self):
        child=Mock(returncode=None,pid=12345)
        with patch.object(self.actor['os'],'waitid',side_effect=ChildProcessError),patch.object(self.actor['os'],'killpg') as kill:
            with self.assertRaises(ChildProcessError):self.actor['stop'](child)
        kill.assert_not_called()
    def test_network_cleanup_owner_internal_guard(self):
        for labels,internal,errors in [({},True,['network_owner_uncertain']),({'signal.permission-fixture':'owner'},False,['network_owner_uncertain'])]:
            run=composition.Campaign();run.owner='owner';run.network_reserved=True;run.docker=Mock(return_value=(0,json.dumps({'labels':labels,'internal':internal}).encode()))
            run.cleanup();self.assertEqual(run.cleanup_errors,errors);self.assertEqual(run.docker.call_count,1)
    def test_network_cleanup_idempotent(self):
        run=composition.Campaign();run.network_reserved=True;run.docker=Mock(side_effect=[(0,json.dumps({'labels':{'signal.permission-fixture':run.owner},'internal':True}).encode()),(0,b'')])
        run.cleanup();run.cleanup();self.assertFalse(run.network_reserved);self.assertFalse(run.cleanup_errors);self.assertEqual(run.docker.call_count,2)
    def test_global_docker_cap_includes_preparation(self):
        run=composition.Campaign();run.commands=55;run.preparation_commands=9
        with self.assertRaises(RuntimeError):run.docker('unreachable')
    def test_actual_journal_parser_rejects_truncated_or_large_record(self):
        with tempfile.TemporaryDirectory() as name:
            path=pathlib.Path(name)/'journal';path.with_name('control').write_bytes(b'SIGAUD01'+__import__('uuid').uuid4().bytes+b'\0'*8);path.write_bytes(b'AUD1')
            with self.assertRaises(RuntimeError):composition.journal(path)
            path.write_bytes(b'AUD1'+(4097).to_bytes(4,'little')+b'\0'*64)
            with self.assertRaises(RuntimeError):composition.journal(path)
    def record(self,sequence=1):
        import uuid
        return {'schema_version':1,'record_id':str(uuid.uuid4()),'producer_id':str(uuid.uuid4()),'sequence':sequence,'timestamp':'2026-10-09T12:00:00Z','actor':{'kind':'system'},'action':{'kind':'configuration_activation','configuration':'runtime','revision_sha256':'a'*64}}
    def frame(self,identity,record):
        body=json.dumps(record).encode();header=b'AUD1'+len(body).to_bytes(4,'little')+composition.hashlib.sha256(b'platform-signal/audit-receiver-frame/v1\0'+identity+body).digest()
        return header+composition.hashlib.sha256(b'platform-signal/audit-receiver-header/v1\0'+identity+header).digest()+body
    def test_control_bound_checksums_and_exact_original(self):
        import uuid
        with tempfile.TemporaryDirectory() as name:
            path=pathlib.Path(name)/'journal';control=path.with_name('control');identity=b'SIGAUD01'+uuid.uuid4().bytes+b'\0'*8;record=self.record();raw=self.frame(identity,record);control.write_bytes(identity);path.write_bytes(raw)
            self.assertEqual(composition.journal(path)[0]['original'],raw[72:])
            for index in (0,8,40,72):
                bad=bytearray(raw);bad[index]^=1;path.write_bytes(bad)
                with self.assertRaises(RuntimeError):composition.journal(path)
            path.write_bytes(raw);control.write_bytes(b'SIGAUD01'+uuid.uuid4().bytes+b'\0'*8)
            with self.assertRaises(RuntimeError):composition.journal(path)
    def test_control_magic_reserved_and_nonzero_uuid(self):
        import uuid
        with tempfile.TemporaryDirectory() as name:
            path=pathlib.Path(name)/'journal';control=path.with_name('control');identity=b'SIGAUD01'+uuid.uuid4().bytes+b'\0'*8
            for bad in [b'BADMAGIC'+identity[8:],identity[:8]+b'\0'*16+identity[24:],identity[:24]+b'\1'+b'\0'*7]:
                control.write_bytes(bad);path.write_bytes(self.frame(bad,self.record()))
                with self.assertRaises(RuntimeError):composition.journal(path)
    def test_record_integer_sequence_and_global_unique_identity(self):
        import uuid
        with tempfile.TemporaryDirectory() as name:
            path=pathlib.Path(name)/'journal';identity=b'SIGAUD01'+uuid.uuid4().bytes+b'\0'*8;path.with_name('control').write_bytes(identity);record=self.record()
            for field,value in [('sequence',True),('sequence',1.0),('sequence',0),('sequence',2**64),('schema_version',True)]:
                bad=copy.deepcopy(record);bad[field]=value;path.write_bytes(self.frame(identity,bad))
                with self.assertRaises(RuntimeError):composition.journal(path)
            bad=copy.deepcopy(record);bad['sequence']=2;path.write_bytes(self.frame(identity,record)+self.frame(identity,bad))
            with self.assertRaises(RuntimeError):composition.journal(path)
            bad['record_id']=str(uuid.uuid4());bad['sequence']=3;path.write_bytes(self.frame(identity,record)+self.frame(identity,bad))
            with self.assertRaises(RuntimeError):composition.journal(path)
    def test_query_pair_requires_bootstrap_granted_success(self):
        import uuid
        first=self.record();first['actor']={'kind':'bootstrap'};operation=str(uuid.uuid4());first['action']={'kind':'access_decision','operation':'query_events','operation_id':operation,'decision':'granted'}
        last=copy.deepcopy(first);last.update(sequence=2,record_id=str(uuid.uuid4()));last['action']={'kind':'operation_completion','operation':'query_events','operation_id':operation,'completion':'success'}
        rows=[{'record':first},{'record':last}];self.assertTrue(composition.query_pair(rows))
        for section,key,value in [('actor','kind','system'),('action','completion','failed'),('action','operation','read_findings')]:
            bad=copy.deepcopy(rows);bad[-1]['record'][section][key]=value;self.assertFalse(composition.query_pair(bad))

if __name__=='__main__':unittest.main()

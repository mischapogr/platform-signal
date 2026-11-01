#!/usr/bin/env python3
"""Synthetic saved-record regressions only; no API calls or product execution."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

SPEC = importlib.util.spec_from_file_location('local_preview', Path(__file__).with_name('check-local-preview.py'))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
COMMIT = '1'*40
IMAGE = 'sha256:'+'2'*64
REFERENCE = 'example.invalid/signal@sha256:'+'3'*64


class PreviewRecords(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'source'
        self.bundle = Path(self.temp.name)/'records'
        self.bundle.mkdir()
        for name in P.INPUTS:
            dst = self.root/name
            dst.parent.mkdir(parents=True,exist_ok=True)
            dst.write_bytes((P.ROOT/name).read_bytes())
        self.root_patch = patch.object(P,'ROOT',self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.expected = json.loads((self.root/'examples/local-preview/events.json').read_bytes())['events']
        self.text('project.txt','signal-preview-abcdef123456\n')
        self.text('source-commit.txt',COMMIT+'\n')
        self.text('image-reference.txt',REFERENCE+'\n')
        self.text('image.txt',IMAGE+' '+json.dumps([REFERENCE])+'\n')
        self.input_hashes()
        for name,status in [('admission-http.txt','202'),('events-http.txt','200'),('findings-http.txt','200')]: self.text(name,status+'\n')
        self.data('admission.json',{'schema_version':1,'accepted':4,'rejected':0,'event_ids':[e['id'] for e in self.expected]})
        self.data('events.json',{'schema_version':1,'events':copy.deepcopy(self.expected),'metadata':{'duration_ms':1,'scanned_files':1,'candidate_partitions':1}})
        self.data('findings.json',{'schema_version':1,'findings':[{'schema_version':1,'id':str(uuid.UUID(int=i+1)),'rule_id':'auth.login-failure','created_at':self.expected[i]['observed_at'],'severity':'medium','title':'Failed login detected','event_ids':[self.expected[i]['id']],'attributes':{}} for i in (1,2)]})

    def text(self,name,value): (self.bundle/name).write_text(value)
    def data(self,name,value): self.text(name,json.dumps(value))
    def read(self,name): return json.loads((self.bundle/name).read_bytes())
    def change(self,name,fn):
        v=self.read(name);fn(v);self.data(name,v)
    def input_hashes(self):
        self.text('inputs.sha256',''.join(hashlib.sha256((self.root/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in P.INPUTS))
    def verify(self): return P.verify(self.bundle,COMMIT,REFERENCE,IMAGE)
    def refuses(self):
        with self.assertRaises((P.PreviewError,OSError,ValueError,TypeError,KeyError)): self.verify()

    def test_synthetic_records_are_only_offline_consistency(self):
        report=self.verify()
        self.assertEqual(report['status'],'consistent_saved_preview_records')
        self.assertEqual(report['scope'],'offline_record_consistency_only')
        for key in ('image_source_build_binding_verified','capture_authenticity_verified','finding_id_derivation_verified','live_requests_performed','browser_verified','durability_or_capacity_qualified','profile_load_completed','alpha_or_release_qualified'):
            self.assertIs(report[key],False)
        self.assertEqual(len(report['input_sha256']),5)
        self.assertEqual(len(report['record_sha256']),11)

    def test_reordered_query_events_allowed(self):
        self.change('events.json',lambda v:v['events'].reverse());self.verify()
    def test_partial_admission_refuses(self):
        self.change('admission.json',lambda v:v.update(accepted=3,rejected=1));self.refuses()
    def test_admission_order_refuses(self):
        self.change('admission.json',lambda v:v['event_ids'].reverse());self.refuses()
    def test_admission_error_refuses(self):
        self.change('admission.json',lambda v:v.update(error={'code':'timeout'}));self.refuses()
    def test_bool_is_not_rejected_count(self):
        self.change('admission.json',lambda v:v.update(rejected=False));self.refuses()
    def test_wrong_get_status_refuses(self): self.text('events-http.txt','503');self.refuses()
    def test_wrong_admission_status_refuses(self): self.text('admission-http.txt','200');self.refuses()
    def test_missing_status_refuses(self): (self.bundle/'findings-http.txt').unlink();self.refuses()
    def test_missing_event_refuses(self):
        self.change('events.json',lambda v:v['events'].pop());self.refuses()
    def test_duplicate_event_replacing_another_refuses(self):
        self.change('events.json',lambda v:v['events'].__setitem__(0,copy.deepcopy(v['events'][1])));self.refuses()
    def test_payload_change_refuses(self):
        self.change('events.json',lambda v:v['events'][0].update(message='mutated'));self.refuses()
    def test_bool_int_payload_confusion_refuses(self):
        self.change('events.json',lambda v:v['events'][0]['attributes']['demo'].update(synthetic=1));self.refuses()
    def test_extra_event_field_refuses(self):
        self.change('events.json',lambda v:v['events'][0].update(unexpected=1));self.refuses()
    def test_wrong_schema_bool_refuses(self):
        self.change('events.json',lambda v:v.update(schema_version=True));self.refuses()
    def test_wrong_rule_refuses(self):
        self.change('findings.json',lambda v:v['findings'][0].update(rule_id='different'));self.refuses()
    def test_duplicate_finding_reference_refuses(self):
        self.change('findings.json',lambda v:v['findings'][0].update(event_ids=v['findings'][1]['event_ids']));self.refuses()
    def test_two_references_refuses(self):
        self.change('findings.json',lambda v:v['findings'][0]['event_ids'].append(self.expected[0]['id']));self.refuses()
    def test_duplicate_finding_uuid_refuses(self):
        self.change('findings.json',lambda v:v['findings'][0].update(id=v['findings'][1]['id']));self.refuses()
    def test_wrong_finding_time_refuses(self):
        self.change('findings.json',lambda v:v['findings'][0].update(created_at='2026-11-02T00:00:00Z'));self.refuses()
    def test_finding_attributes_refuses(self):
        self.change('findings.json',lambda v:v['findings'][0].update(attributes={'unexpected':1}));self.refuses()
    def test_wrong_source_pin_refuses(self): self.text('source-commit.txt','4'*40);self.refuses()
    def test_wrong_image_pin_refuses(self): self.text('image.txt','sha256:'+'4'*64+' '+json.dumps([REFERENCE]));self.refuses()
    def test_wrong_repository_digest_refuses(self): self.text('image.txt',IMAGE+' []');self.refuses()
    def test_unknown_inventory_path_refuses(self):
        with (self.bundle/'inputs.sha256').open('a') as out:out.write('0'*64+'  ../secret\n')
        self.refuses()
    def test_duplicate_inventory_path_refuses(self):
        p=self.bundle/'inputs.sha256';p.write_text(p.read_text()+p.read_text().splitlines()[0]+'\n');self.refuses()
    def test_changed_source_configuration_refuses(self):
        (self.root/'deploy/compose/server.yaml').write_text('changed');self.refuses()
    def test_changed_fixture_even_rehashed_refuses(self):
        p=self.root/'examples/local-preview/events.json';p.write_text('{"events":[]}');self.input_hashes();self.refuses()
    def test_duplicate_json_field_refuses(self): self.text('admission.json','{"accepted":4,"accepted":0}');self.refuses()
    def test_nonfinite_json_refuses(self): self.text('admission.json','{"accepted":NaN}');self.refuses()
    def test_float_overflow_in_ignored_metadata_refuses(self):
        raw=(self.bundle/'events.json').read_text().replace('"duration_ms": 1','"duration_ms": 1e999')
        self.text('events.json',raw);self.refuses()
    def test_finding_derivation_not_promoted(self):
        self.assertIs(self.verify()['finding_id_derivation_verified'],False)
    def test_oversize_record_refuses(self): self.text('events.json',' '* (P.LIMIT+1));self.refuses()
    def test_symlink_record_refuses(self):
        p=self.bundle/'events.json';p.unlink();p.symlink_to(self.bundle/'admission.json');self.refuses()
    def test_hardlink_record_refuses(self):
        p=self.bundle/'events.json';p.unlink();os.link(self.bundle/'admission.json',p);self.refuses()
    def test_fifo_record_refuses_without_open_blocking(self):
        p=self.bundle/'events.json';p.unlink();os.mkfifo(p);self.refuses()
    def test_directory_symlink_refuses(self):
        alias=Path(self.temp.name)/'alias';alias.symlink_to(self.bundle,target_is_directory=True)
        with self.assertRaises(OSError): P.verify(alias,COMMIT,REFERENCE,IMAGE)
    def test_file_changed_during_read_refuses(self):
        path=Path(self.temp.name)/'mutable';path.write_bytes(b'old')
        original=P.os.read
        def mutate(fd,count):
            raw=original(fd,count)
            if raw==b'old': path.write_bytes(b'changed-length')
            return raw
        with patch.object(P.os,'read',side_effect=mutate):
            with self.assertRaises(P.PreviewError): P.read_regular(path)
    def test_bad_cli_does_not_echo_unknown_values(self):
        secret='sentinel-unknown-argument'
        with patch('sys.argv',['check-local-preview.py','--unknown',secret]),contextlib.redirect_stdout(io.StringIO()) as output,contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(P.main(),1)
        self.assertNotIn(secret,output.getvalue()+errors.getvalue())
    def test_error_output_does_not_echo_input_or_path(self):
        secret='sentinel-do-not-print'
        with patch('sys.argv',['check-local-preview.py','--evidence',str(self.bundle/secret),'--source-commit',COMMIT,'--image-reference',REFERENCE,'--image-id',IMAGE]),contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(P.main(),1)
        self.assertNotIn(secret,output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['status'],'invalid_or_incomplete_preview_records')


if __name__=='__main__': unittest.main()

#!/usr/bin/env python3
"""Focused fixed-schema UID/DAC false-positive regressions (no Docker)."""
import importlib.util
import pathlib
import unittest
import copy
import sys
import os
import tempfile
import subprocess
from unittest.mock import Mock
spec = importlib.util.spec_from_file_location('permission_fixture', pathlib.Path(__file__).with_name('check-audit-receiver-permissions.py'))
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)

class PermissionTests(unittest.TestCase):
    def value(self, positive=False):
        uid=1000 if positive else 1001
        names=['root-list']+[n+'-'+op for n in ('control','journal','config','key','secret') for op in ('read','write')]
        if not positive:names.append('root-create')
        identity={'Uid':[uid]*4,'Gid':[uid]*4,'Groups':[uid],'CapEff':'0000000000000000','NoNewPrivs':[1]}
        return {'identity':identity,'pid1_identity':copy.deepcopy(identity),'root_owner':1000,'root_mode':0o700,'results':[{'name':n,'errno':0 if positive else 13} for n in names]}
    def accepted(self,v,positive=False):return fixture.valid_probe(v,1000 if positive else 1001,1000 if positive else 1001,1000,positive)
    def test_actual_eacces_and_eperm(self):
        v=self.value();self.assertTrue(self.accepted(v));v['results'][0]['errno']=1;self.assertTrue(self.accepted(v))
    def test_owner_positive(self):self.assertTrue(self.accepted(self.value(True),True))
    def test_absence_readonly_success_never_dac(self):
        for errno in (2,30,0,-1):
            with self.subTest(errno=errno):
                v=self.value();v['results'][0]['errno']=errno;self.assertFalse(self.accepted(v))
    def test_identity_fences(self):
        for key,value in [('Uid',[0]*4),('Gid',[0]*4),('Groups',[1001,0]),('CapEff','1'),('NoNewPrivs',[0])]:
            with self.subTest(key=key):
                v=self.value();v['identity'][key]=value;self.assertFalse(self.accepted(v))
    def test_pid1_must_have_same_actual_fences(self):
        v=self.value();v['pid1_identity']['Uid']=[0]*4;self.assertFalse(self.accepted(v))
    def test_owner_or_mode_mismatch(self):
        for key,value in [('root_owner',0),('root_mode',0o755)]:
            v=self.value();v[key]=value;self.assertFalse(self.accepted(v))
    def test_missing_duplicate_rows(self):
        v=self.value();v['results'].pop();self.assertFalse(self.accepted(v))
        v=self.value();v['results'][-1]=copy.deepcopy(v['results'][0]);self.assertFalse(self.accepted(v))
    def test_cleanup_never_removes_foreign_label(self):
        runner=fixture.Bounded();runner.names=['reserved'];runner.docker=Mock(return_value=(0,b'{"signal.permission-fixture":"foreign"}'))
        runner.cleanup();self.assertEqual(runner.cleanup_errors,['container_owner_mismatch']);self.assertEqual(runner.docker.call_count,1)
    def test_cleanup_distinguishes_notfound_from_uncertain(self):
        for raw,errors in [(b'Error: No such object: reserved\n',[]),(b'permission denied',['container_inspection_uncertain'])]:
            runner=fixture.Bounded();runner.names=['reserved'];runner.docker=Mock(return_value=(1,raw));runner.cleanup();self.assertEqual(runner.cleanup_errors,errors)
    def test_notfound_must_be_exact_known_line_and_name(self):
        for raw in (b'Error: No such object: reserved-extra\n',b'Error: No such object: other\n',
                    b'Error: No such object: reserved\npermission denied\n',b'prefix Error: No such object: reserved\n',
                    b'Error: No such object: reserved',b'Error: No such object: reserved\n\n'):
            with self.subTest(raw=raw):
                runner=fixture.Bounded();runner.names=['reserved'];runner.docker=Mock(return_value=(1,raw));runner.cleanup()
                self.assertEqual(runner.cleanup_errors,['container_inspection_uncertain']);self.assertEqual(runner.names,['reserved'])
    def test_successful_resource_cleanup_is_idempotent(self):
        runner=fixture.Bounded();runner.names=['reserved'];runner.docker=Mock(side_effect=[(0,('{"signal.permission-fixture":"'+runner.owner+'"}').encode()),(0,b'')])
        runner.cleanup();runner.cleanup();self.assertFalse(runner.names);self.assertFalse(runner.cleanup_errors);self.assertEqual(runner.docker.call_count,2)
    def test_failed_create_remains_reserved(self):
        runner=fixture.Bounded();runner.docker=Mock(return_value=(1,b'failure'))
        with self.assertRaises(RuntimeError):runner.create('receiver',1000,1000,pathlib.Path('/private'),pathlib.Path('/probe'),['hold'])
        self.assertEqual(len(runner.names),1)
    def test_command_bound_preserves_cleanup_reserve(self):
        runner=fixture.Bounded();runner.commands=48
        with self.assertRaises(RuntimeError):runner.command(['unreachable'])
    def test_command_output_is_finitely_capped(self):
        runner=fixture.Bounded()
        with self.assertRaises(RuntimeError):runner.command([sys.executable,'-c','import os; os.write(1,b"a"*4096)'],limit=1024)
        self.assertFalse(runner.children)
    def test_one_group_retirement_before_reap(self):
        runner=fixture.Bounded()
        with unittest.mock.patch.object(fixture.os,'killpg',wraps=fixture.os.killpg) as kill:
            code,raw=runner.command([sys.executable,'-c','print("fixed-result")'])
        self.assertEqual(code,0);self.assertEqual(raw,b'fixed-result\n');self.assertEqual(kill.call_count,1);self.assertFalse(runner.children)
    def test_interruption_at_signal_restore_keeps_child_registered(self):
        runner=fixture.Bounded();original=fixture.signal.pthread_sigmask
        def interrupt(how,mask):
            value=original(how,mask)
            if how==fixture.signal.SIG_SETMASK:raise RuntimeError('simulated_pending_interrupt')
            return value
        with unittest.mock.patch.object(fixture.signal,'pthread_sigmask',side_effect=interrupt):
            with self.assertRaises(RuntimeError):runner.command([sys.executable,'-c','import time; time.sleep(10)'])
        self.assertEqual(len(runner.children),1)
        with unittest.mock.patch.object(fixture.os,'killpg',wraps=fixture.os.killpg) as kill:
            runner.cleanup();runner.cleanup()
        self.assertFalse(runner.children);self.assertFalse(runner.cleanup_errors);self.assertEqual(kill.call_count,1)
    def test_reaped_registered_child_never_signalled(self):
        child=subprocess.Popen([sys.executable,'-c','pass'],start_new_session=True)
        child.wait(timeout=2);runner=fixture.Bounded();runner.children.add(child)
        with unittest.mock.patch.object(fixture.os,'killpg') as kill:
            runner.cleanup();runner.cleanup()
        self.assertFalse(runner.children);kill.assert_not_called()
    def test_unknown_child_retained_without_pid_signal(self):
        runner=fixture.Bounded();child=Mock(returncode=None,pid=12345);runner.children.add(child)
        with unittest.mock.patch.object(fixture.os,'waitid',side_effect=ChildProcessError), unittest.mock.patch.object(fixture.os,'killpg') as kill:
            runner.cleanup()
        self.assertIn(child,runner.children);self.assertEqual(runner.cleanup_errors,['child_retirement_uncertain']);kill.assert_not_called()
    def test_hash_rejects_fifo_special_symlink_before_open(self):
        with tempfile.TemporaryDirectory() as name:
            root=pathlib.Path(name);os.mkfifo(root/'fifo');(root/'file').write_bytes(b'a');(root/'link').symlink_to(root/'file')
            for path in (root/'fifo',root/'link',root):
                with self.subTest(path=path), unittest.mock.patch.object(fixture.os,'open') as opened:
                    with self.assertRaises(RuntimeError):fixture.digest(path)
                    opened.assert_not_called()
    def test_hash_initial_size_cap(self):
        with tempfile.TemporaryDirectory() as name:
            path=pathlib.Path(name)/'file';path.write_bytes(b'abcd')
            with unittest.mock.patch.object(fixture.os,'open') as opened:
                with self.assertRaises(RuntimeError):fixture.digest(path,3)
                opened.assert_not_called()
            self.assertEqual(fixture.digest(path,4),fixture.hashlib.sha256(b'abcd').hexdigest())
    def test_hash_growth_is_capped_during_read(self):
        with tempfile.TemporaryDirectory() as name:
            path=pathlib.Path(name)/'file';path.write_bytes(b'abc');original=fixture.os.read;grown=False
            def grow(fd,size):
                nonlocal grown
                block=original(fd,size)
                if not grown:
                    with path.open('ab') as output:output.write(b'defg')
                    grown=True
                return block
            with unittest.mock.patch.object(fixture.os,'read',side_effect=grow):
                with self.assertRaisesRegex(RuntimeError,'read_capacity'):fixture.digest(path,3)
    def test_private_inventory_has_entry_and_byte_caps(self):
        with tempfile.TemporaryDirectory() as name:
            root=pathlib.Path(name);(root/'directory').mkdir();(root/'directory/file').write_bytes(b'abcd')
            self.assertEqual(len(fixture.private_snapshot(root,2,4)),1)
            with self.assertRaisesRegex(RuntimeError,'entry_capacity'):fixture.private_snapshot(root,1,4)
            with self.assertRaises(RuntimeError):fixture.private_snapshot(root,2,3)
    def test_private_inventory_rejects_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as name:
            root=pathlib.Path(name);os.mkfifo(root/'fifo')
            with self.assertRaisesRegex(RuntimeError,'file_type'):fixture.private_snapshot(root)
            (root/'fifo').unlink();(root/'link').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(RuntimeError,'file_type'):fixture.private_snapshot(root)
    def test_provenance_requires_exact_accepted_source_binding(self):
        with tempfile.TemporaryDirectory() as name:
            path=pathlib.Path(name)/'binary.json'
            value={'sha256':fixture.PIN,'binary':str(fixture.BINARY),'source_sha256':copy.deepcopy(fixture.ACCEPTED_SOURCE)}
            path.write_text(fixture.json.dumps(value));self.assertEqual(fixture.read_provenance(path),value)
            value['source_sha256']['Cargo.lock']='0'*64;path.write_text(fixture.json.dumps(value))
            with self.assertRaisesRegex(RuntimeError,'provenance_mismatch'):fixture.read_provenance(path)

if __name__=='__main__':unittest.main()

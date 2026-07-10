#!/usr/bin/env python3
"""Acceptance of actual simulator output exhaustion and termination cleanup."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('object_query',ROOT/'scripts/check-object-query.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)

class ProcessBounds(unittest.TestCase):
    def test_output_overflow_kills_owned_producer_and_retains_only_cap(self):
        with tempfile.TemporaryDirectory(prefix='signal-query-log-') as directory:
            run=gate.Run(Path(directory),Path(sys.executable))
            child=run.spawn([sys.executable,'-c','import os; os.write(1,b"x"*(2*1024*1024))'],dict(os.environ),'overflow')
            run.server=child
            try:
                child.wait(timeout=5);run.reap_log(child)
                self.assertEqual((run.out/'overflow.log').stat().st_size,1024*1024)
                self.assertTrue(run.log_errors)
                with self.assertRaises(RuntimeError):run.check_logs()
                self.assertFalse(run.drains)
            finally:self.assertEqual(run.cleanup(),[])
    def test_spawn_evidence_failure_keeps_child_in_owned_cleanup_registry(self):
        with tempfile.TemporaryDirectory(prefix='signal-query-spawn-') as directory:
            run=gate.Run(Path(directory),Path(sys.executable))
            with mock.patch.object(gate,'write_json',side_effect=OSError('injected evidence failure')):
                with self.assertRaises(OSError):run.spawn([sys.executable,'-c','import time; time.sleep(8)'],dict(os.environ),'creation')
            children=list(run.owned.values());self.assertEqual(len(children),1)
            self.assertEqual(run.cleanup(),[]);self.assertIsNotNone(children[0].returncode);self.assertFalse(run.owned)
    def test_creation_signal_is_deferred_until_child_is_registered(self):
        with tempfile.TemporaryDirectory(prefix='signal-query-create-term-') as directory:
            run=gate.Run(Path(directory),Path(sys.executable));real_popen=subprocess.Popen
            def interrupted_creation(*args,**kwargs):
                child=real_popen(*args,**kwargs)
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None)
                return child
            with mock.patch.object(gate.subprocess,'Popen',side_effect=interrupted_creation):
                with self.assertRaises(KeyboardInterrupt):run.spawn([sys.executable,'-c','import time; time.sleep(8)'],dict(os.environ),'creation-signal')
            children=list(run.owned.values());self.assertEqual(len(children),1)
            self.assertEqual(run.cleanup(),[]);self.assertIsNotNone(children[0].returncode);self.assertFalse(run.owned)
    def test_cleanup_attempts_second_child_after_first_wait_failure(self):
        with tempfile.TemporaryDirectory(prefix='signal-query-cleanup-two-') as directory:
            run=gate.Run(Path(directory),Path(sys.executable))
            first=run.spawn([sys.executable,'-c','import time; time.sleep(8)'],dict(os.environ),'first')
            second=run.spawn([sys.executable,'-c','import time; time.sleep(8)'],dict(os.environ),'second')
            try:
                with mock.patch.object(first,'wait',side_effect=OSError('injected wait failure')):errors=run.cleanup()
                self.assertEqual(len(errors),1);self.assertEqual(errors[0]['pid'],first.pid)
                self.assertIsNotNone(second.returncode);self.assertNotIn(second.pid,run.owned)
                self.assertIn(first.pid,run.owned)
            finally:self.assertEqual(run.cleanup(),[])
    def test_cleanup_errors_persist_failed_report_and_cannot_return_success(self):
        with tempfile.TemporaryDirectory(prefix='signal-query-cleanup-') as directory:
            output=Path(directory)/'failed'
            previous={kind:signal.getsignal(kind) for kind in [signal.SIGTERM,signal.SIGINT]}
            try:
                with mock.patch.object(sys,'argv',['check-object-query','--output',str(output)]), mock.patch.object(gate.Run,'run',return_value={'events':[]}), mock.patch.object(gate.Run,'cleanup',return_value=[{'pid':0,'error':'injected failure'}]), mock.patch('builtins.print'):
                    with self.assertRaises(RuntimeError):gate.main()
                report=json.loads((output/'report.json').read_text());self.assertEqual(report['status'],'failed');self.assertTrue(report['cleanup_errors'])
            finally:
                for kind,handler in previous.items():signal.signal(kind,handler)
    def test_sigterm_records_failure_and_reaps_both_real_children(self):
        with tempfile.TemporaryDirectory(prefix='signal-query-term-') as directory:
            output=Path(directory)/'evidence'
            child=subprocess.Popen([sys.executable,str(ROOT/'scripts/check-object-query.py'),'--output',str(output)],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            records=[]
            try:
                until=time.monotonic()+8
                while time.monotonic()<until:
                    p=output/'processes.json'
                    if p.exists():
                        records=json.loads(p.read_text())
                        if len(records)==2:break
                    if child.poll() is not None:self.fail('runner ended before termination witness')
                    time.sleep(.005)
                self.assertEqual(len(records),2)
                child.send_signal(signal.SIGTERM);self.assertNotEqual(child.wait(timeout=12),0)
                report=json.loads((output/'report.json').read_text())
                self.assertEqual(report['status'],'failed')
                self.assertNotIn('cleanup_errors',report)
                self.assertEqual(len(report['processes']),2)
                for process in report['processes']:
                    self.assertIsNotNone(process['return_code'])
                    with self.assertRaises(ProcessLookupError):os.kill(process['pid'],0)
            finally:
                if child.poll() is None:child.kill()
                child.wait(timeout=5)
                # Guard only the exact fixture/server processes spawned for this root.
                for process in records:
                    try:
                        args=Path(f'/proc/{process["pid"]}/cmdline').read_bytes()
                        owned_fixture=str(output).encode() in args
                        owned_server=False
                        if args.split(b'\0')[0]==str(ROOT/'target/debug/signal-server').encode():
                            environment=Path(f'/proc/{process["pid"]}/environ').read_bytes()
                            owned_server=(b'SIGNAL_WAL_DIR='+str(output/'server/wal').encode()+b'\0') in environment
                        if owned_fixture or owned_server:os.kill(process['pid'],signal.SIGKILL)
                    except (FileNotFoundError,ProcessLookupError):pass
if __name__=='__main__':unittest.main()

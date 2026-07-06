#!/usr/bin/env python3
"""Linux regression: the hardening timeout kills its owned child process group."""
import ctypes
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

SCRIPT = Path(__file__).with_name('check-hardening.py')
spec = importlib.util.spec_from_file_location('hardening', SCRIPT)
hardening = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hardening)


class TimeoutCleanup(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux', 'campaign targets Linux')
    def test_timeout_kills_and_reaps_owned_parent_and_sleeper(self):
        # Only this regression process becomes a subreaper, so it can reap its
        # own orphaned test grandchild rather than depending on container PID 1.
        libc = ctypes.CDLL(None, use_errno=True)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)  # PR_SET_CHILD_SUBREAPER
        sentinel = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        owned = []
        try:
            with tempfile.TemporaryDirectory(prefix='signal-hardening-cleanup-') as temp:
                path = Path(temp) / 'pids.json'
                child_code = 'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)'
                parent_code = '''import json,os,pathlib,signal,subprocess,sys,time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen([sys.executable, '-c', sys.argv[2]])
pathlib.Path(sys.argv[1]).write_text(json.dumps([os.getpid(), child.pid]))
time.sleep(30)
'''
                start = time.monotonic()
                with (Path(temp) / 'log').open('wb') as log:
                    code = hardening.run_bounded([sys.executable, '-c', parent_code, str(path), child_code],
                                                 log, timeout=2, grace=0.2)
                self.assertEqual(code, 124)
                self.assertLess(time.monotonic() - start, 4)
                self.assertTrue(path.exists(), 'owned sleeper was not started')
                owned = json.loads(path.read_text())
                parent, grandchild = owned
                # run_bounded reaps its direct child. The subreaper fixture reaps
                # the killed grandchild, proving it cannot continue after return.
                self.assertFalse(Path(f'/proc/{parent}').exists())
                deadline = time.monotonic() + 2
                reaped = False
                while time.monotonic() < deadline:
                    waited, status = os.waitpid(grandchild, os.WNOHANG)
                    if waited == grandchild:
                        self.assertTrue(os.WIFSIGNALED(status))
                        self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                        reaped = True
                        break
                    time.sleep(0.01)
                self.assertTrue(reaped, 'grandchild survived process-group timeout')
                self.assertFalse(Path(f'/proc/{grandchild}').exists())
                self.assertIsNone(sentinel.poll(), 'cleanup touched an unrelated process')
        finally:
            # Failure cleanup touches only recorded owned PIDs, never a broad group.
            for pid in owned:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            sentinel.kill()
            sentinel.wait(timeout=2)


if __name__ == '__main__':
    unittest.main()

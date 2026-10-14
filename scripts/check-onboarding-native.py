#!/usr/bin/env python3
"""Prepare a fresh bounded fixture and exec the owned native identity composition."""
import json
import os
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
if len(sys.argv) not in (3,4) or (len(sys.argv)==4 and sys.argv[3]!='--window'):
    raise SystemExit('usage: check-onboarding-native.py BINARY OWNED_OUTPUT [--window]')
binary, root = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
if not root.is_relative_to(REPO / 'target') or root.exists() or not binary.is_file():
    raise SystemExit('fresh owned target output and built binary required')
root.mkdir(parents=True)
# Explicit laboratory budgets, independent of changing runtime defaults.
(root / 'coverage-limits.json').write_text(json.dumps({
    'max_payloads': 128, 'max_identities': 128, 'max_bindings': 32,
    'max_ledger_bytes': 4194304, 'max_database_pages': 1024,
    'max_journal_bytes': 146800640, 'operation_capacity': 4,
    'transient_memory_bytes': 16777216, 'worker_memory_bytes': 8388608,
    'max_vm_steps': 10000000, 'operation_timeout_ms': 1000}) + '\n')
env = dict(os.environ, SIGNAL_TEST_ONBOARDING='1')
env.pop('SIGNAL_TEST_WINDOW',None)
if len(sys.argv)==4:env['SIGNAL_TEST_WINDOW']='1'
os.execvpe(sys.executable, [sys.executable, str(REPO / 'tests/integration/access-server-process.py'),
                          str(binary), str(root)], env)

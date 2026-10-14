#!/usr/bin/env python3
"""Verify native gates cannot pass from absent capture or delivery simulation."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]

def main():
    # Deliberately remove capture/CI selectors, without inspecting credentials.
    env={k:v for k,v in os.environ.items() if not k.startswith('SIGNAL_') and k not in {'GITHUB_ACTIONS','GITHUB_SHA'}}
    with tempfile.TemporaryDirectory(prefix='runtime-refusal-',dir=ROOT/'target') as directory:
        root=Path(directory)
        for name,flags in [('native-without-runner',['--capture-only']),('simulation-as-native',['--capture-only','--simulate'])]:
            result=subprocess.run(['python3','scripts/check-runtime-sensor.py',*flags,'--output',str(root/name)],cwd=ROOT,env=env,capture_output=True,timeout=10)
            assert result.returncode!=0
            assert not list((root/name).glob('NATIVE*.json')), 'no native success report'
        result=subprocess.run(['cargo','test','-p','signal-collector-sdk','--test','falco','--','--ignored','--exact','native_capture_projects_all_owned_hooks_and_explicit_health_counters'],cwd=ROOT,env=env,capture_output=True,timeout=120)
        assert result.returncode!=0 and b'owned capture directory' in result.stdout+result.stderr, 'native projection refuses absent manifest'
        scoped=dict(env,SIGNAL_OWNED_FALCO_CAPTURE=str(root.relative_to(ROOT)))
        result=subprocess.run(['cargo','test','-p','signal-collector-sdk','--test','falco','--','--ignored','--exact','native_capture_projects_all_owned_hooks_and_explicit_health_counters'],cwd=ROOT,env=scoped,capture_output=True,timeout=120)
        assert result.returncode!=0 and b'native capture manifest' in result.stdout+result.stderr, 'relative workspace capture resolves before missing-manifest refusal'

    print(json.dumps({'status':'passed','checks':4,'native_kernel_capture':False}))

if __name__=='__main__':main()

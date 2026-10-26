#!/usr/bin/env python3
"""Actual Small loading of exact packaged rules, persistence and crash restart."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('baseline_pipeline', ROOT / 'scripts/check-security-requirements.py')
PIPE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PIPE)
PACK = ROOT / 'rules/baselines/v1'
IDS = ['SIG-D01', 'SIG-D02', 'SIG-D03', 'SIG-D05', 'SIG-D07']
PATHS = ['rules/baselines/v1/manifest.json', *['rules/baselines/v1/'+i+'.yaml' for i in IDS],
         'crates/signal-rules/src/baseline.rs', 'crates/signal-rules/src/lib.rs',
         'crates/signal-rules/src/revision.rs', 'Cargo.toml', 'Cargo.lock',
         'apps/signal-server/src/main.rs', 'apps/signal-server/src/runtime_config.rs',
         'scripts/check-baseline-pack.py', 'scripts/test-baseline-pack.py', 'scripts/check-security-requirements.py',
         'tests/fixtures/security-requirements/catalog.json']


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def hashes():
    return {p: digest(ROOT / p) for p in PATHS}


def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        PIPE.require(key not in result, 'duplicate pack JSON key')
        result[key] = value
    return result


def load_rules():
    path = PACK / 'manifest.json'
    PIPE.require(not path.is_symlink() and path.stat().st_size <= 65536, 'bounded owned manifest')
    manifest = json.loads(path.read_bytes(), object_pairs_hook=pairs_unique)
    PIPE.require(manifest['schema_version'] == 1 and manifest['revision'] == '1.0.0', 'known pack version')
    PIPE.require([d['id'] for d in manifest['detections']] == IDS, 'exact pack inventory')
    rules = {}
    for entry in manifest['detections']:
        name = entry['id']+'.yaml'
        PIPE.require(entry['rule_file'] == name, 'fixed rule basename')
        path = PACK / name
        PIPE.require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 65536, 'bounded owned rule')
        raw = path.read_bytes()
        PIPE.require(hashlib.sha256(raw).hexdigest() == entry['rule_sha256'], 'pack rule digest')
        rules[name] = raw
    return rules


def checkpoint(path):
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return False
    return (len(raw) == 28 and raw[:8] == b'SIGACK01'
            and zlib.crc32(raw[:24]) == int.from_bytes(raw[24:], 'little')
            and int.from_bytes(raw[8:16], 'little') == 15
            and int.from_bytes(raw[16:24], 'little') == 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    PIPE.require(output.is_relative_to((ROOT / 'target').resolve()), 'owned output')
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    sources = hashes()
    report = {'schema_version': 1, 'status': 'failed', 'source_sha256': sources,
              'scope': 'actual Small/exact shipped YAML/WAL/Parquet/findings/restart; synthetic canonical fixtures',
              'limits': ['not host readiness/coverage authentication', 'no AWS/EKS/native ARM64/production qualification']}
    process = None
    began = time.monotonic()
    try:
        rules = load_rules()
        (output / 'rules').mkdir()
        for name, raw in rules.items():
            (output / 'rules' / name).write_bytes(raw)
        catalog, _ = PIPE.load_catalog(ROOT / 'tests/fixtures/security-requirements/catalog.json')
        detections = [d for d in catalog['detections'] if d['id'] in IDS]
        events = [f['events'][0] for d in detections for f in d['fixtures']]
        expected = {(d['id'], d['fixtures'][0]['events'][0]['id']) for d in detections}
        process, address = PIPE.start(args.server.resolve(), output, 1)
        status, ack = PIPE.request(address, 'POST', '/v1/events/batch', {'events': events})
        PIPE.require(status == 202 and ack['event_ids'] == [e['id'] for e in events], 'actual original WAL admission')
        deadline = time.monotonic()+20
        rows = findings = []
        while time.monotonic() < deadline:
            rows, findings = PIPE.snapshot(address)
            if len(rows) == 15 and len(findings) == 5 and checkpoint(output / 'wal/checkpoint'):
                break
            time.sleep(0.025)
        PIPE.require(len(rows) == 15 and checkpoint(output / 'wal/checkpoint'), 'all originals published before checkpoint')
        PIPE.require({(f['rule_id'], f['event_ids'][0]) for f in findings} == expected and len(findings) == 5, 'exact five positive findings')
        PIPE.require(sorted(rows, key=lambda r:r['id']) == sorted(events, key=lambda r:r['id']), 'original canonical events preserved')
        process.kill()
        PIPE.require(process.wait(timeout=5) == -signal.SIGKILL, 'owned actual SIGKILL')
        process, address = PIPE.start(args.server.resolve(), output, 2)
        after_rows, after_findings = PIPE.snapshot(address)
        PIPE.require(sorted(after_rows, key=lambda r:r['id']) == sorted(rows, key=lambda r:r['id']), 'events survive restart exactly')
        PIPE.require(sorted(after_findings, key=lambda r:r['id']) == sorted(findings, key=lambda r:r['id']), 'findings survive restart exactly')
        PIPE.require(hashes() == sources, 'pack/runtime source drift')
        report.update(status='passed_local', persisted_events=15, persisted_findings=5,
                      exact_pack_files_loaded=True, actual_sigkill=True, original_findings_survive_restart=True,
                      wal_checkpoint=15, server_sha256=digest(args.server), pack_manifest_sha256=sources['rules/baselines/v1/manifest.json'])
    finally:
        cleanup_error = None
        try:
            if process is not None:
                PIPE.stop(process)
        except BaseException as error:
            cleanup_error = type(error).__name__
            report['status'] = 'failed'
            report['cleanup_error'] = cleanup_error
        report['owned_cleanup'] = cleanup_error is None
        report['elapsed_seconds'] = round(time.monotonic()-began, 3)
        (output / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
        PIPE.require(cleanup_error is None, 'owned process cleanup failed')
    print(json.dumps({'status': report['status'], 'report': str(output / 'report.json')}))


if __name__ == '__main__':
    main()

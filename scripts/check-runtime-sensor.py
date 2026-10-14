#!/usr/bin/env python3
"""Bounded owned Falco capture and agent outage replay on isolated CI runners."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import selectors
import socket
import struct
import subprocess
import time
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'falcosecurity/falco@sha256:d0cfe422d6ac0e0f20857798f46c7d7273210e1b064b22821e4e6e7f843cde6b'
MAX_CAPTURE = 2 * 1024 * 1024
MAX_LINE = 65536
TIMEOUT = 90


def rules(executable):
    assert not any(c in str(executable) for c in "'\n\r\\")
    base = 'seq=%evt.num time=%evt.rawtime type=%evt.type result=%evt.rawres pid=%proc.pid start=%proc.pid.ts ppid=%proc.ppid parent_start=%proc.ppid.ts exe=%proc.exepath'
    definitions = [
        ('execution', 'evt.type in (execve,execveat)', ''),
        ('file access', 'evt.type in (open,openat,openat2)', ' path=%fd.name read=%evt.is_open_read'),
        ('connection', 'evt.type=connect and fd.type=ipv4', ' ip=%fd.sip port=%fd.sport'),
    ]
    return '\n'.join(f'- rule: SIGNAL fixture {name}\n  desc: Owned synthetic runtime qualification\n  condition: {condition} and proc.exepath=\'{executable}\'\n  output: "{base}{extra}"\n  priority: INFORMATIONAL\n' for name, condition, extra in definitions)


def configuration():
    # A complete owned fixture selection; no image config.d or container plugins.
    return """config_files: []
rules_files:
  - /fixture/rules.yaml
load_plugins: []
plugins: []
engine:
  kind: modern_ebpf
json_output: true
json_include_output_property: false
json_include_message_property: false
json_include_tags_property: false
stdout_output:
  enabled: true
buffered_outputs: false
log_stderr: true
log_syslog: false
webserver:
  enabled: false
metrics:
  enabled: true
  interval: 1s
  include_empty_values: true
  resource_utilization_enabled: true
  rules_counters_enabled: true
  state_counters_enabled: true
  kernel_event_counters_enabled: true
  output_rule: true
"""


def run_command(command, deadline, **kwargs):
    subprocess.run(command, timeout=max(.01, deadline-time.monotonic()), check=True, **kwargs)


def report_preflight():
    cap = next(l.split()[1] for l in Path('/proc/self/status').read_text().splitlines() if l.startswith('CapEff:'))
    return {'kernel': platform.release(), 'architecture': platform.machine(), 'kernel_btf': Path('/sys/kernel/btf/vmlinux').exists(), 'effective_capabilities': cap, 'isolated_github_runner': os.environ.get('GITHUB_ACTIONS') == 'true'}


def capture(output):
    # No kernel loading on developer machines. This gate is explicitly for the
    # disposable CI job environment, with read-only host mounts and no network.
    assert os.environ.get('GITHUB_ACTIONS') == 'true', 'native capture requires isolated GitHub runner'
    assert Path('/sys/kernel/btf/vmlinux').exists(), 'native kernel BTF required'
    deadline = time.monotonic() + TIMEOUT
    executable = output/'signal-rt'
    source = ROOT/'tests/integration/runtime-sensor-fixture.c'
    run_command(['cc', '-Wall', '-Wextra', '-Werror', '-O2', str(source), '-o', str(executable)], deadline)
    protected = output/'synthetic-protected-asset'
    protected.write_bytes(b'synthetic fixture material only\n')
    rule_file = output/'rules.yaml'
    rule_file.write_text(rules(executable))
    (output/'falco.yaml').write_text(configuration())
    run_command(['docker', 'pull', IMAGE], deadline, stdout=subprocess.DEVNULL)
    architecture = subprocess.check_output(['docker','image','inspect',IMAGE,'--format','{{.Architecture}}'],timeout=5,text=True).strip()
    assert architecture == {'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine()), 'native sensor architecture'
    owned = 'signal-runtime-'+uuid.uuid4().hex[:12]
    command = ['docker', 'run', '--rm', '--name', owned, '--network=none', '--pid=host', '--cap-drop=ALL', '--cap-add=SYS_ADMIN', '--cap-add=SYS_RESOURCE', '--cap-add=SYS_PTRACE', '-e', 'HOST_ROOT=/host', '-v', '/proc:/host/proc:ro', '-v', '/sys/kernel/btf:/sys/kernel/btf:ro', '-v', '/sys/kernel/tracing:/sys/kernel/tracing:ro', '-v', f'{output}:/fixture:ro', '--entrypoint', '/usr/bin/falco', IMAGE,
               '-c', '/fixture/falco.yaml', '-r', '/fixture/rules.yaml']
    listener = socket.socket()
    listener.bind(('127.0.0.1',0));listener.listen(1)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    selected = selectors.DefaultSelector();selected.register(process.stdout, selectors.EVENT_READ)
    lines, pending, total, fixture_ran, ended, kinds, metrics = [], bytearray(), 0, False, None, set(), []
    fixture_pid = None
    native_events = []
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None: raise AssertionError('native Falco exited before capture completed')
            for key, _ in selected.select(.1):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block: raise AssertionError('native capture pipe ended')
                total += len(block);assert total <= MAX_CAPTURE, 'native capture byte capacity'
                pending.extend(block)
                while b'\n' in pending:
                    line, _, rest = pending.partition(b'\n');pending=bytearray(rest)
                    assert len(line)<=MAX_LINE, 'native record byte capacity'
                    lines.append(bytes(line));assert len(lines)<=512, 'native capture record capacity'
                    if not line.startswith(b'{'): continue
                    value=json.loads(line)
                    if value.get('source')=='internal': metrics.append(value)
                    if value.get('source')=='syscall':
                        kinds.add(value['output_fields']['evt.type']);native_events.append(value)
                assert len(pending)<=MAX_LINE, 'partial native record capacity'
            if metrics and not fixture_ran:
                # A real native metrics record proves the engine opened; startup
                # log text alone never grants ready/capture acceptance.
                fixture_process=subprocess.Popen([str(executable),str(protected),str(listener.getsockname()[1])])
                fixture_pid=fixture_process.pid
                try:assert fixture_process.wait(timeout=max(.01,deadline-time.monotonic()))==0, 'owned fixture process'
                finally:
                    if fixture_process.poll() is None:fixture_process.kill();fixture_process.wait(timeout=3)
                fixture_ran=True;ended=time.monotonic()+3
            if fixture_ran and ended is not None and time.monotonic()>=ended: break
        assert fixture_ran and {'execve','openat','connect'}<=kinds, f'missing owned native hooks: {kinds}'
        assert len(metrics)>=2, 'before/after native metrics required'
        before,after=metrics[0]['output_fields'],metrics[-1]['output_fields']
        assert all(e['output_fields']['proc.pid']==fixture_pid and e['output_fields']['proc.ppid']==os.getpid() for e in native_events), 'actual owned PID/parent source binding'
        assert all(before['evt.time']<=e['output_fields']['evt.rawtime']<=after['evt.time'] for e in native_events), 'independent observed capture interval'
        counters=['scap.n_evts','scap.n_drops','falco.outputs_queue_num_drops','falco.n_failed_fd_lookups','falco.n_failed_thread_lookups','falco.n_drops_full_threadtable','falco.n_store_evts_drops','falco.n_retrieve_evts_drops']
        for key in counters:assert isinstance(before[key],int) and isinstance(after[key],int) and 0<=before[key]<=after[key], 'native counter continuity'
        for key in ['falco.start_ts','falco.reload_ts','falco.host_boot_ts']:assert before[key]==after[key], 'sensor/boot/reload continuity'
        assert before['scap.engine_name']==after['scap.engine_name']=='modern_bpf' and before['falco.version']==after['falco.version']=='0.44.1'
        observer={'owned_pid':fixture_pid,'owned_parent':os.getpid(),'capture_interval_verified':True,'counter_deltas':{key:after[key]-before[key] for key in counters},'coverage':'not_assessed','reason':'finite fixture does not assess full host visibility or independent production expectations'}
    finally:
        original=b'\n'.join(l for l in lines if l.startswith(b'{'))+b'\n'
        (output/'native.jsonl').write_bytes(original)
        (output/'sensor-startup.log').write_bytes(b'\n'.join(l for l in lines if not l.startswith(b'{'))+b'\n')
        listener.close();selected.close()
        # Name is freshly generated and owned; never address unrelated containers.
        subprocess.run(['docker','stop','--time','2',owned],timeout=8,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        if process.poll() is None: process.kill()
        process.wait(timeout=5)
        process.stdout.close()
        subprocess.run(['docker','rm','--force',owned],timeout=8,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
    original=b'\n'.join(l for l in lines if l.startswith(b'{'))+b'\n'
    assert len(original)<=MAX_CAPTURE
    (output/'native.jsonl').write_bytes(original)
    (output/'sensor-startup.log').write_bytes(b'\n'.join(l for l in lines if not l.startswith(b'{'))+b'\n')
    inspect=subprocess.run(['docker','ps','-a','--filter','name=^/'+owned+'$','--format','{{.Names}}'],timeout=5,capture_output=True,check=True,text=True)
    assert not inspect.stdout.strip(), 'owned sensor container cleanup'
    return {'image':IMAGE,'architecture':architecture,'rule_sha256':hashlib.sha256(rule_file.read_bytes()).hexdigest(),'capture_command':command,'observer':observer,'version':'0.44.1','boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'hooks':sorted(kinds),'raw_sha256':hashlib.sha256(original).hexdigest(),'raw_bytes':len(original),'source_sha':os.environ.get('GITHUB_SHA','local'),'cleanup':True}


def wait(predicate,label,seconds=8):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.025)
    raise AssertionError(label)


def replay(agent, server, output, boot):
    def port():
        with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
    api, mp = port(), port()
    env={k:v for k,v in os.environ.items() if not k.startswith('SIGNAL_')}
    env['SIGNAL_API_TOKEN']='synthetic-runtime-token';env['SIGNAL_AGENT_API_TOKEN']='synthetic-runtime-token'
    log=output/'input.jsonl';log.write_bytes((output/'native.jsonl').read_bytes())
    spool=output/'spool';processes=[]
    def start(name,args, process_env=None):
        with (output/(name+'.log')).open('wb') as f:p=subprocess.Popen(args,cwd=ROOT,env=process_env or env,stdout=f,stderr=f)
        processes.append(p);return p
    def request(p,path):
        c=http.client.HTTPConnection('127.0.0.1',p,timeout=1)
        try:
            c.request('GET',path,headers={'Authorization':'Bearer synthetic-runtime-token'});r=c.getresponse();b=r.read(MAX_CAPTURE+1)
            if r.status!=200 or len(b)>MAX_CAPTURE:raise ValueError('bounded API response')
            return b
        finally:c.close()
    def records():
        events=[]
        for p in sorted(spool.glob('record-*')):
            raw=p.read_bytes();assert len(raw)<131072
            length,crc,hcrc=struct.unpack('<III',raw[:12]);assert len(raw)==length+12
            assert zlib.crc32(raw[:8])==hcrc and zlib.crc32(raw[12:])==crc
            events.append(json.loads(raw[12:])['event'])
        return events
    native=[json.loads(l) for l in log.read_text().splitlines()]
    count=len(native);assert 3<=count<=128
    args=[str(agent),'--server',f'http://127.0.0.1:{api}','--spool-dir',str(spool),'--file',str(log),'--format','falco-json','--runtime-boot-id',boot,'--source-name','owned-runtime-host','--source-type','runtime','--metrics-listen',f'127.0.0.1:{mp}','--flush-ms','20','--retry-base-ms','20','--retry-max-ms','100']
    def admitted():
        try:return len(records())==count
        except (OSError,ValueError,struct.error):return False
    try:
        agent_process=start('offline-agent',args);wait(admitted,'synced complete native capture')
        retained=records();assert agent_process.poll() is None
        agent_process.kill();assert agent_process.wait(timeout=5)==-9
        server_env=dict(env,SIGNAL_LISTEN=f'127.0.0.1:{api}',SIGNAL_WAL_DIR=str(output/'wal'),SIGNAL_STORAGE_DIR=str(output/'events'),SIGNAL_FINDINGS_DIR=str(output/'findings'),SIGNAL_STORAGE_FLUSH_MS='10')
        server_process=start('server',[str(server)],server_env)
        def ready():
            try:request(api,'/readyz');return True
            except (OSError,ValueError,http.client.HTTPException):return False
        wait(ready,'server readiness')
        start('restarted-agent',args)
        def delivered():
            try:return len(json.loads(request(api,'/v1/events?source_name=owned-runtime-host&limit=1000'))['events'])>=count
            except (OSError,ValueError,KeyError,http.client.HTTPException):return False
        wait(delivered,'native capture replay',15)
        events=json.loads(request(api,'/v1/events?source_name=owned-runtime-host&limit=1000'))['events']
        by_id={e['id']:e for e in events}
        for event in retained:assert by_id.get(event['id'])==event, 'exact canonical ID/value replay'
        assert all(e['attributes']['evidence']['runtime_sensor_coverage']=='not_assessed' for e in events)
        syscall=[e for e in events if 'process' in e['attributes']]
        assert {e['attributes']['runtime']['kind'] for e in syscall}>={'execution','file_open','connection'}
        identities={(e['attributes']['process']['pid'],e['attributes']['process']['start_epoch_ns'],e['attributes']['process']['boot_id']) for e in syscall}
        assert len(identities)==1, 'same owned process identity across hooks'
        metrics=[e['attributes']['sensor_health'] for e in events if 'sensor_health' in e['attributes']]
        assert len(metrics)>=2 and all(m['engine']=='modern_bpf' and m['version']=='0.44.1' for m in metrics)
        (output/'canonical.json').write_text(json.dumps(retained,indent=2)+'\n')
        return {'admitted':count,'retained_ids':len(retained),'replay_values_exact':True,'process_identities':len(identities),'native_metrics':len(metrics),'coverage':'not_assessed'}
    finally:
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=4)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=4)
        assert all(p.poll() is not None for p in processes)


def simulated_capture(output):
    # Delivery-only fixture. Never claims kernel hooks, capability or native proof.
    import datetime
    n=time.time_ns();stamp=datetime.datetime.fromtimestamp(n//1_000_000_000,datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')+f'.{n%1_000_000_000:09d}Z'
    records=[]
    for sequence,operation in enumerate(['execve','openat','connect'],1):
        fields={'evt.num':sequence,'evt.rawtime':n,'evt.type':operation,'evt.rawres':0,'proc.pid':1234,'proc.pid.ts':n-10000,'proc.ppid':1233,'proc.ppid.ts':n-20000,'proc.exepath':'/synthetic/owned-runtime'}
        if operation=='openat':fields.update({'fd.name':'/synthetic/protected-asset','evt.is_open_read':True})
        if operation=='connect':fields.update({'fd.sip':'127.0.0.1','fd.sport':443})
        records.append({'source':'syscall','time':stamp,'output_fields':fields})
    for count in [100,200]:
        fields={'evt.source':'syscall','evt.time':n,'falco.start_ts':n-1000,'falco.reload_ts':n-1000,'falco.host_boot_ts':n-20000,'scap.n_evts':count,'scap.n_drops':0,'falco.outputs_queue_num_drops':0,'scap.engine_name':'modern_bpf','falco.version':'0.44.1','falco.n_failed_fd_lookups':0,'falco.n_failed_thread_lookups':0,'falco.n_drops_full_threadtable':0,'falco.n_store_evts_drops':0,'falco.n_retrieve_evts_drops':0}
        records.append({'source':'internal','time':stamp,'rule':'Falco internal: metrics snapshot','output_fields':fields})
    raw=b''.join(json.dumps(r).encode()+b'\n' for r in records);(output/'native.jsonl').write_bytes(raw)
    return {'simulation':True,'boot_id':str(uuid.UUID(int=1)),'raw_sha256':hashlib.sha256(raw).hexdigest(),'raw_bytes':len(raw),'cleanup':True}


def retained_native_capture(directory, output):
    directory=directory.resolve();directory.relative_to(ROOT/'target')
    manifest=directory/'NATIVE-CAPTURE.json';raw_path=directory/'native.jsonl'
    assert manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size<=65536
    assert raw_path.is_file() and not raw_path.is_symlink() and raw_path.stat().st_size<=MAX_CAPTURE
    source=json.loads(manifest.read_text());raw=raw_path.read_bytes()
    assert source['status']=='passed_native_capture' and not source.get('simulation')
    assert hashlib.sha256(raw).hexdigest()==source['raw_sha256']
    (output/'native.jsonl').write_bytes(raw)
    return {'native_capture_source_sha':source['source_sha'],'captured_architecture':source['architecture'],'raw_sha256':source['raw_sha256'],'boot_id':source['boot_id'],'execution_scope':'local replay of retained capture; no new kernel execution'}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');parser.add_argument('--simulate',action='store_true');parser.add_argument('--capture-only',action='store_true');parser.add_argument('--replay-capture',type=Path);parser.add_argument('--agent',type=Path);parser.add_argument('--server',type=Path);parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    output=args.output.resolve();output.relative_to(ROOT/'target');output.mkdir(parents=True,exist_ok=False)
    preflight=report_preflight();(output/'preflight.json').write_text(json.dumps(preflight,indent=2)+'\n')
    if args.preflight:print(json.dumps(preflight));return
    assert not (args.replay_capture and (args.simulate or args.capture_only)), 'retained replay cannot grant native execution'
    assert not (args.simulate and args.capture_only), 'simulation cannot grant capture-only native evidence'
    if args.capture_only:
        summary=capture(output);summary['status']='passed_native_capture'
        (output/'NATIVE-CAPTURE.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary));return
    assert args.agent and args.server
    summary=retained_native_capture(args.replay_capture,output) if args.replay_capture else (simulated_capture(output) if args.simulate else capture(output));summary['replay']=replay(args.agent.resolve(),args.server.resolve(),output,summary['boot_id']);summary['status']='passed_local_retained_native_delivery' if args.replay_capture else ('passed_simulated_delivery' if args.simulate else 'passed_native_selected_runtime')
    (output/('RETAINED-NATIVE-DELIVERY.json' if args.replay_capture else ('SIMULATED-DELIVERY.json' if args.simulate else 'NATIVE-HOST-RUNTIME.json'))).write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))

if __name__=='__main__':main()

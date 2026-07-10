#!/usr/bin/env python3
"""Real monolith + owned persistent S3 simulation; no AWS or custody qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, build_opener, ProxyHandler
import uuid
import zlib

ROOT=Path(__file__).resolve().parents[1]
TOKEN='synthetic-object-query-token'
MAX_HTTP=1024*1024

def file_hash(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def read_json(path,capacity=256*1024):
    with path.open('rb') as stream:data=stream.read(capacity+1)
    if len(data)>capacity:raise RuntimeError('JSON evidence capacity')
    return json.loads(data)

def write_json(path,value):
    data=json.dumps(value,indent=2).encode()+b'\n'
    if len(data)>256*1024:raise RuntimeError('JSON evidence capacity')
    temporary=path.with_suffix('.tmp')
    with temporary.open('wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(temporary,path)

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def http(url,method='GET',body=None):
    raw=None if body is None else json.dumps(body).encode()
    request=Request(url,data=raw,method=method,headers={'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'})
    opener=build_opener(ProxyHandler({}))
    try:response=opener.open(request,timeout=2)
    except HTTPError as e:response=e
    with response:
        result=response.read(MAX_HTTP+1)
        if len(result)>MAX_HTTP:raise RuntimeError('HTTP response capacity')
        return response.status,result

class Run:
    def __init__(self,out,binary):
        self.out,self.binary=out,binary
        self.fixture_id=str(uuid.uuid4());self.fixture_root=out/'fixture';self.fixture_root.mkdir()
        self.server_root=out/'server';self.server_root.mkdir();self.server_port=port();self.url=f'http://127.0.0.1:{self.server_port}'
        self.fixture=None;self.server=None;self.fixture_port=0;self.generation=0;self.logs=[];self.scenarios=[];self.drains={};self.log_errors={};self.processes=[];self.owned={}
        rules=self.server_root/'rules';rules.mkdir()
        (rules/'generic.yml').write_text('apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: generic.object-query\n  name: Generic fixture event\nspec:\n  severity: medium\n  match:\n    all:\n      - field: source.type\n        eq: query-simulation\n  finding:\n    title: Generic query fixture finding\n')
    def check_logs(self):
        if self.log_errors:raise RuntimeError('bounded process output failed')
        for path in self.logs:
            if path.exists() and path.stat().st_size>1024*1024:raise RuntimeError('process log capacity')
    def wait(self,test,seconds=12):
        until=time.monotonic()+seconds
        while time.monotonic()<until:
            self.check_logs()
            if test():return
            time.sleep(.02)
        raise RuntimeError('bounded simulation deadline')
    def spawn(self,command,env,label):
        if len(self.owned)>=2 or len(self.logs)>=16:raise RuntimeError('owned process/log capacity')
        path=self.out/(label+'.log');self.logs.append(path)
        # Popen construction and registry insertion form one ownership milestone.
        # Deferral avoids inheriting a blocked signal mask into the owned child.
        pending=[]
        previous={kind:signal.getsignal(kind) for kind in (signal.SIGTERM,signal.SIGINT)}
        def defer(kind,_frame):
            if not pending:pending.append(kind)
        try:
            for kind in previous:signal.signal(kind,defer)
            child=subprocess.Popen(command,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            self.owned[child.pid]=child
            self.processes.append({'label':label,'pid':child.pid,'return_code':None})
        finally:
            for kind,handler in previous.items():signal.signal(kind,handler)
        if pending:raise KeyboardInterrupt('owned creation interrupted by signal '+str(pending[0]))
        def drain():
            try:
                retained=0
                with path.open('xb') as output:
                    while True:
                        chunk=child.stdout.read(8192)
                        if not chunk:break
                        remaining=1024*1024-retained
                        output.write(chunk[:remaining]);output.flush();retained+=min(len(chunk),remaining)
                        if len(chunk)>remaining:
                            self.log_errors[label]='capacity';child.kill();break
            except Exception:
                self.log_errors[label]='drain failure'
                if child.poll() is None:child.kill()
            finally:child.stdout.close()
        thread=threading.Thread(target=drain,name='signal-fixture-log-'+label,daemon=True)
        self.drains[child.pid]=thread;thread.start()
        write_json(self.out/'processes.json',self.processes)
        return child
    def reaped(self,child):
        for record in self.processes:
            if record['pid']==child.pid:record['return_code']=child.returncode
        self.owned.pop(child.pid,None)
        write_json(self.out/'processes.json',self.processes)
    def reap_log(self,child):
        thread=self.drains.get(child.pid)
        if thread is not None:
            thread.join(timeout=1)
            if thread.is_alive():raise RuntimeError('bounded log drain did not finish')
            self.drains.pop(child.pid,None)
    def start_fixture(self):
        old=self.fixture_root/'endpoint.json'
        if old.exists():old.unlink()
        self.fixture=self.spawn([sys.executable,str(ROOT/'scripts/fixtures/s3-query-server.py'),'--root',str(self.fixture_root),'--fixture-id',self.fixture_id,'--port',str(self.fixture_port)],dict(os.environ),'fixture-'+str(self.generation))
        self.wait(lambda:old.exists())
        endpoint=read_json(old);self.endpoint=endpoint['url'];self.fixture_port=int(self.endpoint.rsplit(':',1)[1])
    def env(self):
        env={k:v for k,v in os.environ.items() if not k.startswith('SIGNAL_')}
        env.update({'SIGNAL_LISTEN':f'127.0.0.1:{self.server_port}','SIGNAL_API_TOKEN':TOKEN,
            'SIGNAL_WAL_DIR':str(self.server_root/'wal'),'SIGNAL_STORAGE_DIR':str(self.server_root/'control'),
            'SIGNAL_FINDINGS_DIR':str(self.server_root/'findings'),'SIGNAL_RULE_DIRS':str(self.server_root/'rules'),
            'SIGNAL_STORAGE_TYPE':'s3','SIGNAL_S3_ENDPOINT':self.endpoint,'SIGNAL_S3_REGION':'eu-central-1',
            'SIGNAL_S3_BUCKET':'signal-fixture','SIGNAL_S3_BACKEND_ID':self.fixture_id,
            'SIGNAL_S3_CACHE_DIR':str(self.server_root/'derived'),'SIGNAL_S3_CACHE_FILES':'32',
            'SIGNAL_S3_CACHE_BYTES':str(32*1024*1024),'SIGNAL_S3_INVENTORY_OBJECTS':'128',
            'SIGNAL_S3_OBJECT_BYTES':str(8*1024*1024),'SIGNAL_STORAGE_BYTES':str(64*1024*1024),
            'SIGNAL_S3_ACCESS_KEY':'synthetic-query-access','SIGNAL_S3_SECRET_KEY':'synthetic-query-secret',
            'SIGNAL_S3_SESSION_TOKEN':'synthetic-query-session','SIGNAL_S3_ALLOW_LOOPBACK_HTTP':'true',
            'SIGNAL_STORAGE_BATCH_EVENTS':'1','SIGNAL_STORAGE_FLUSH_MS':'10',
            'SIGNAL_STORAGE_TIMEOUT_MS':'5000','SIGNAL_QUERY_TIMEOUT_MS':'1000','SIGNAL_SHUTDOWN_TIMEOUT_MS':'2000'})
        return env
    def start_server(self):
        self.generation+=1;self.server=self.spawn([str(self.binary)],self.env(),'server-'+str(self.generation))
        def ready():
            if self.server.poll() is not None:raise RuntimeError('server startup failed; see bounded owned log')
            try:return http(self.url+'/readyz')[0]==200
            except (URLError,ConnectionError,TimeoutError):return False
        self.wait(ready)
    def stop(self,name,kill=False):
        child=getattr(self,name)
        if child is None:return
        if child.poll() is None:
            child.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
        code=child.wait(timeout=5);self.reap_log(child);self.reaped(child);setattr(self,name,None)
        if kill and code!=-signal.SIGKILL:raise RuntimeError('expected actual owned SIGKILL')
        if name=='server' and not kill and code!=0:raise RuntimeError('graceful server shutdown failed')
    def fault(self,mode):write_json(self.fixture_root/'fault.json',{'mode':mode})
    def checkpoint(self):
        p=self.server_root/'wal/checkpoint'
        data=p.read_bytes()
        if len(data)!=28 or data[:8]!=b'SIGACK01' or zlib.crc32(data[:24])!=struct.unpack('<I',data[24:])[0]:raise RuntimeError('WAL checkpoint witness')
        return struct.unpack('<Q',data[8:16])[0]
    def admit(self,hour,message):
        event={'timestamp':f'2026-07-10T{hour:02d}:00:00Z','source':{'type':'query-simulation'},'severity':'error','message':message,'attributes':{'nested':{'values':[1,True,'value']}}}
        code,body=http(self.url+'/v1/events','POST',event)
        if code!=202:raise RuntimeError('expected synced WAL admission')
        data=json.loads(body)
        if data['accepted']!=1 or len(data['event_ids'])!=1:raise RuntimeError('admission response')
        return data['event_ids'][0]
    def events(self,hour=None):
        query={'source_type':'query-simulation','limit':'100'}
        if hour is not None:query.update({'from':f'2026-07-10T{hour:02d}:00:00Z','to':f'2026-07-10T{hour+1:02d}:00:00Z'})
        code,body=http(self.url+'/v1/events?'+urlencode(query))
        if code!=200:raise RuntimeError(f'event query status {code}')
        return json.loads(body)
    def stable_events(self,expected):
        result={}
        def check():
            nonlocal result
            try:result=self.events();return len(result['events'])==len(expected) and {e['id'] for e in result['events']}==set(expected)
            except (RuntimeError,URLError,TimeoutError,ConnectionError):return False
        self.wait(check)
        return result
    def finding_ids(self):
        code,body=http(self.url+'/v1/findings?limit=100')
        if code!=200:raise RuntimeError('findings query')
        return {f['id']:f for f in json.loads(body)['findings']}
    def record(self,name,**details):self.scenarios.append({'name':name,'status':'passed_simulated',**details})
    def run(self):
        self.start_fixture();self.start_server()
        a=self.admit(19,'first');self.wait(lambda:self.checkpoint()==1)
        b=self.admit(20,'second');self.wait(lambda:self.checkpoint()==2)
        before=self.stable_events([a,b]);findings=self.finding_ids()
        if len(findings)!=2:raise RuntimeError('deterministic fixture findings')
        log=self.fixture_root/'requests.jsonl';offset=log.stat().st_size
        selected=self.events(19)
        if [e['id'] for e in selected['events']]!=[a] or selected['metadata']['scanned_files']!=1:raise RuntimeError('selected partition query')
        rows=[json.loads(x) for x in log.read_bytes()[offset:].splitlines()]
        data_reads=[r for r in rows if r['method']=='GET' and '.parquet' in r['key']]
        if len(data_reads)!=1 or 'hour%3D19' not in data_reads[0]['key'] and 'hour=19' not in data_reads[0]['key']:raise RuntimeError('remote GET pruning witness')
        self.record('committed_search_findings_and_remote_pruning',checkpoint=2,event_ids=[a,b],finding_ids=list(findings),data_reads=data_reads)
        for mode in ['deny-data','corrupt-data','deny-list','throttle-list','malformed-list','oversized-control','outage']:
            self.fault(mode);code,body=http(self.url+'/v1/events?limit=100')
            if code==200 or 'events' in json.loads(body):raise RuntimeError('fault returned successful/partial events')
            self.fault('normal');self.stable_events([a,b]);self.record('query-'+mode,http_status=code,checkpoint=self.checkpoint())
        self.stop('server');derived=self.server_root/'derived'
        if not derived.is_dir() or derived.is_symlink():raise RuntimeError('owned derived cache absent')
        shutil.rmtree(derived)
        self.start_server();after=self.stable_events([a,b])
        if before['events']!=after['events'] or self.finding_ids()!=findings:raise RuntimeError('rebuild changed canonical identities')
        self.record('stopped_cache_delete_rebuild',event_ids=[a,b],finding_ids=list(findings))
        self.fault('pause-data');c=self.admit(21,'crash after unreferenced data object')
        self.wait(lambda:(self.fixture_root/'effect.json').exists(),seconds=2)
        if self.checkpoint()!=2 or read_json(self.fixture_root/'effect.json')['stage']!='synced_data_before_reply':raise RuntimeError('orphan checkpoint/effect witness')
        self.stop('server',kill=True);self.fault('normal');self.stop('fixture',kill=True)
        self.start_fixture();self.start_server();self.wait(lambda:self.checkpoint()==3)
        orphan_events=self.stable_events([a,b,c]);orphan_findings=self.finding_ids()
        original={e['id']:e for e in before['events']}; recovered={e['id']:e for e in orphan_events['events']}
        if not all(recovered[k]==v for k,v in original.items()):raise RuntimeError('orphan recovery changed canonical events')
        if len(orphan_findings)!=3 or len(read_json(self.fixture_root/'catalog.json'))!=6:raise RuntimeError('orphan reuse duplicated/lost query data')
        self.record('actual_data_orphan_sigkill_and_exact_reuse',checkpoint=3,event_ids=[a,b,c],finding_ids=list(orphan_findings))
        (self.fixture_root/'effect.json').unlink()
        self.fault('pause-manifest');d=self.admit(22,'crash between manifest and local head')
        self.wait(lambda:(self.fixture_root/'effect.json').exists(),seconds=2)
        if self.checkpoint()!=3 or read_json(self.fixture_root/'effect.json')['stage']!='synced_manifest_before_reply':raise RuntimeError('early checkpoint before manifest reply/head')
        self.stop('server',kill=True);self.fault('normal');self.stop('fixture',kill=True)
        self.start_fixture();self.start_server();self.wait(lambda:self.checkpoint()==4)
        final=self.stable_events([a,b,c,d]);new_findings=self.finding_ids()
        recovered={e['id']:e for e in final['events']}
        if not all(recovered[e['id']]==e for e in orphan_events['events']):raise RuntimeError('manifest recovery changed canonical events')
        if len(new_findings)!=4 or not all(new_findings[k]==v for k,v in orphan_findings.items()):raise RuntimeError('crash replay changed deterministic findings')
        catalog=read_json(self.fixture_root/'catalog.json');commits=[k for k in catalog if '/commits/' in k]
        if len(commits)!=4 or len(catalog)!=8:raise RuntimeError('duplicate commit/object after uncertain replay')
        self.record('actual_server_and_source_sigkill_uncertain_manifest_replay',checkpoint=4,event_ids=[a,b,c,d],finding_ids=list(new_findings),commits=commits)
        self.stop('server');self.stop('fixture')
        self.check_logs()
        for path in self.logs:
            data=path.read_bytes()
            for sentinel in [TOKEN,'synthetic-query-access','synthetic-query-secret','synthetic-query-session']:
                if sentinel.encode() in data:raise RuntimeError('secret sentinel leaked into process logs')
        return final
    def cleanup(self):
        errors=[]
        for pid,child in list(self.owned.items()):
            try:
                if child.poll() is None:child.kill()
                child.wait(timeout=5);self.reap_log(child)
                if child.stdout is not None:child.stdout.close()
                self.reaped(child)
                for name in ['server','fixture']:
                    if getattr(self,name) is child:setattr(self,name,None)
            except Exception as error:errors.append({'pid':pid,'error':type(error).__name__})
        return errors

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--binary',type=Path,default=ROOT/'target/debug/signal-server');args=parser.parse_args()
    output=args.output.absolute();binary=args.binary.absolute()
    if output.exists() or binary.is_symlink() or not binary.is_file():raise RuntimeError('fresh output and built binary required')
    output.mkdir(parents=True);run=Run(output,binary);started=time.monotonic()
    report={'schema_version':1,'status':'in_progress','full_release':False,'scope':'Owned persistent loopback S3 and real server processes only','binary_sha256':file_hash(binary)}
    try:
        final=run.run();report.update(status='passed_simulated',scenarios=run.scenarios,event_count=len(final['events']))
    except BaseException as e:
        report.update(status='failed',scenarios=run.scenarios,error=type(e).__name__+': '+str(e));raise
    finally:
        # Repeated external signals cannot interrupt the finite cleanup/report path.
        signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
        cleanup_errors=run.cleanup()
        if cleanup_errors:report.update(status='failed',cleanup_errors=cleanup_errors)
        report['processes']=run.processes
        report['elapsed_seconds']=round(time.monotonic()-started,3);report['external_exceptions']=['AWS/IAM/KMS/Object Lock/TLS runtime','native ARM64/EKS/shared HA','source custody/completeness'];report['logs']={str(p.relative_to(output)):file_hash(p) for p in run.logs if p.exists()};write_json(output/'report.json',report)
    print(json.dumps(report,indent=2))
    if report['status']!='passed_simulated':raise RuntimeError('simulation cleanup failed; retained report')
if __name__=='__main__':
    def interrupted(signum,_frame):raise KeyboardInterrupt('owned simulation interrupted by signal '+str(signum))
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    main()

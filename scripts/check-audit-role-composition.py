#!/usr/bin/env python3
"""Bounded four nonzero-UID native audit composition using immutable cached inputs."""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import signal
import struct
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('role_dac', ROOT/'scripts/check-audit-receiver-permissions.py')
DAC = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(DAC)
NODE = 'sha256:b37a4d56eedb5e42bca59c8d4782fa550e741fba5dbce943c53767d3ceee57e6'
PYTHON = 'sha256:3dc0132ee978305990b529498077dbe8ab756c7e655221cad18d807feb878a51'
PROBE = ROOT/'target/goal-execution-20261007/SECURITY-AUDIT/receiver-permissions-task-guard-corrected/permission-probe'
PROBE_PIN = 'ceba4ff05d5ab8493376b20b85d96ed6bf279bbcc31e0bd749424fc21645bb29'
RUNTIME_CAP = 16777216

# This public helper runs in P/H and supervises the real M child. Credentials and
# original audit bytes are supplied only through separately mounted private files.
ACTOR = r'''
import base64,datetime,hashlib,http.client,io,json,os,pathlib,resource,signal,socket,ssl,subprocess,sys,time,uuid
os.umask(0o077)
PRIVATE=pathlib.Path('/private');PROFILE=PRIVATE/'profile.json';ROLE=sys.argv[2] if sys.argv[1]=='pid1' else None
NEGATIVE_OVERRIDE=None
STEP='actor_setup'
OWNED_ADDRESSES={}
def strict_json(raw):
 def pairs(values):
  result={}
  for key,value in values:
   if key in result:raise ValueError('duplicate_json_field')
   result[key]=value
  return result
 return json.loads(raw,object_pairs_hook=pairs)
def read(path,cap=65536):
 with open(path,'rb') as f:data=f.read(cap+1)
 if len(data)>cap:raise RuntimeError('private_input_capacity')
 return data
def write(path,value):
 path=pathlib.Path(path);path.write_text(json.dumps(value));path.chmod(0o600)
def identity(pid='self'):
 status=pathlib.Path('/proc/'+str(pid)+'/status').read_text();out={}
 for field in ['Uid','Gid','Groups','CapEff','NoNewPrivs']:
  v=next(line.split(':',1)[1].strip() for line in status.splitlines() if line.startswith(field+':'))
  out[field]=v if field=='CapEff' else [int(n) for n in v.split()]
 return out
def profile():return json.loads(read(PROFILE))
def context(p,role,certificate=True):
 c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);c.check_hostname=True;c.verify_mode=ssl.CERT_REQUIRED
 c.load_verify_locations(cadata=p[role+'_ca'])
 if certificate:c.load_cert_chain('/private/client.pem','/private/client.key')
 return c
def request(c,host,port,path,token=None,method='GET',body=None,cap=65536,tls_probe=False):
 def expired(*_):raise TimeoutError('original_http_deadline')
 old=signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,2)
 conn=http.client.HTTPSConnection(host,port,context=c,timeout=2)
 try:
  # Retain the initially resolved owned container address through stop/start;
  # HTTPSConnection still wraps TLS with the original host as server_hostname.
  if host not in OWNED_ADDRESSES:OWNED_ADDRESSES[host]=socket.gethostbyname(host)
  conn._create_connection=lambda endpoint,timeout,source_address=None:socket.create_connection((OWNED_ADDRESSES[host],endpoint[1]),timeout,source_address)
  if tls_probe:
   conn.connect();conn.sock.recv(1);raise RuntimeError('missing_explicit_tls_rejection')
  headers={'Content-Type':'application/json'}
  if token is not None:headers['Authorization']='Bearer '+token
  conn.request(method,path,body,headers);res=conn.getresponse();raw=res.read(cap+1)
  if len(raw)>cap:raise RuntimeError('response_capacity')
  headers={}
  for k,v in res.getheaders():
   k=k.lower();headers[k]=v if k not in headers else None
  return res.status,raw,headers
 finally:conn.close();signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old)
FIELDS={'schema_version','held','records','bytes','record_capacity','byte_capacity','physical_depth','physical_capacity','physical_rejected','rejected','uncertain','append_http_depth','append_http_capacity','append_http_rejected','health_http_rejected'}
def health(p):
 code,raw,h=request(context(p,'health'),'receiver',8082,'/v1/audit/health',p['token'],cap=1024)
 value=strict_json(raw)
 if code not in (200,503) or h.get('cache-control')!='no-store' or h.get('content-type')!='application/json' or ('content-length' in h and (h['content-length'] is None or not h['content-length'].isdigit() or int(h['content-length'])>1024)) or set(value)!=FIELDS or type(value['held']) is not bool:raise RuntimeError('health_bad')
 if any(type(value[k]) is not int or not 0<=value[k]<=18446744073709551615 for k in FIELDS-{'held'}):raise RuntimeError('health_numeric_shape')
 if value['schema_version']!=1 or not 1<=value['record_capacity']<=16384 or not 4168<=value['byte_capacity']<=67108864 or value['records']>value['record_capacity'] or value['bytes']>value['byte_capacity'] or value['physical_capacity']!=1 or value['physical_depth']>1 or value['append_http_capacity']!=1 or value['append_http_depth']>1 or (code==503)!=value['held']:raise RuntimeError('health_bounds_status')
 return value
def exited(child):return os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None
def stop(child,kill=False):
 if child is None:return None
 if child.returncode is not None:return child.returncode
 if not exited(child):
  os.killpg(child.pid,signal.SIGKILL if kill else signal.SIGTERM)
  end=time.monotonic()+1.5
  while not exited(child) and time.monotonic()<end:time.sleep(.02)
 # The leader remains unreaped throughout escalation and still pins its PID.
 try:os.killpg(child.pid,signal.SIGKILL)
 except ProcessLookupError:pass
 child.wait(timeout=1)
 return child.returncode
def pid1(role):
 global STEP
 STEP='private_profile_copy'
 PRIVATE.mkdir(exist_ok=True,mode=0o700)
 p=json.loads(read('/input/profile'));write(PROFILE,p)
 for name in ['client.pem','client.key']:
  if name in p:
   (PRIVATE/name).write_text(p[name]);(PRIVATE/name).chmod(0o600)
 child=None;generation=-1;status='stopped';end=time.monotonic()+160;running=True;observations=0;last_good=0
 def shutdown(*_):
  nonlocal running
  running=False
 signal.signal(signal.SIGTERM,shutdown);signal.signal(signal.SIGINT,shutdown)
 if role=='monolith':
  STEP='monolith_private_layout'
  for d in ['outbox','wal','events','findings','rules']:(PRIVATE/d).mkdir(mode=0o700)
  (PRIVATE/'rules/rule.yaml').write_text(p['rule']);write(PRIVATE/'audit-tls',p['audit_tls']);write(PRIVATE/'api-tls',p['api_tls'])
 try:
  while running and time.monotonic()<end:
   if role=='monolith':
    try:control=json.loads(read('/input/control',256))
    except (ValueError,FileNotFoundError):time.sleep(.03);continue
    if control['generation']!=generation:
     action=control['action'];exit_code=stop(child,action=='kill');child=None;generation=control['generation'];status='stopped'
     if action in ('bootstrap','active'):
      STEP='native_monolith_spawn'
      audit=dict(p['audit']);
      if action=='active':audit['configuration_activations']=['runtime','rules']
      write(PRIVATE/'audit.json',audit)
      env={'PATH':'/usr/local/bin:/usr/bin:/bin','RUST_LOG':'warn','SIGNAL_LISTEN':'0.0.0.0:8080','SIGNAL_API_TOKEN':p['api_token'],'SIGNAL_TLS_CONFIG':'/private/api-tls','SIGNAL_AUDIT_CONFIG':'/private/audit.json','SIGNAL_AUDIT_TOKEN':p['token'],'SIGNAL_WAL_DIR':'/private/wal','SIGNAL_STORAGE_DIR':'/private/events','SIGNAL_FINDINGS_DIR':'/private/findings','SIGNAL_RULE_DIRS':'/private/rules','SIGNAL_STORAGE_FLUSH_MS':'20','SIGNAL_STORAGE_BATCH_EVENTS':'1','SIGNAL_REQUEST_TIMEOUT_MS':'1000','SIGNAL_QUERY_TIMEOUT_MS':'1000','SIGNAL_CONNECTION_TIMEOUT_MS':'3000','SIGNAL_SHUTDOWN_TIMEOUT_MS':'1000'}
      def cap():resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576))
      with open('/private/monolith.log','ab') as log:child=subprocess.Popen(['/native/ld-linux-x86-64.so.2','--library-path','/native','/server'],env=env,stdout=log,stderr=log,start_new_session=True,preexec_fn=cap)
      status='running'
     value={'generation':generation,'state':status,'identity':identity(),'pid1_identity':identity(1),'last_exit':exit_code}
     if child is not None:
      STEP='native_identity_read';value['native_identity']=identity(child.pid)
     write(PRIVATE/'status',value)
    if child is not None and exited(child):
     exit_code=stop(child);child=None;status='native_failed'
     write(PRIVATE/'status',{'generation':generation,'state':status,'identity':identity(),'pid1_identity':identity(1),'last_exit':exit_code})
   elif role=='health':
    observations+=1
    if observations>256:raise RuntimeError('health_observation_capacity')
    try:
     snapshot=health(p)
     if not snapshot['held']:last_good=time.monotonic_ns()
     value={'status':'observed','records':snapshot['records'],'held':snapshot['held'],'record_capacity':snapshot['record_capacity'],'byte_capacity':snapshot['byte_capacity']}
    except (OSError,http.client.HTTPException,ValueError,RuntimeError):value={'status':'unavailable'}
    value.update(monotonic_ns=time.monotonic_ns(),observations=observations,last_good_receipt_ns=last_good);write(PRIVATE/'health',value)
   time.sleep(.2 if role=='health' else .03)
 finally:stop(child)
def fresh_observation(current,prior,after,expected):
 if current.get('monotonic_ns',0)<=after or current.get('observations',0)<=prior.get('observations',0):return False
 if expected=='unavailable':return current.get('status')=='unavailable' and 'last_good_receipt_ns' in prior and current.get('last_good_receipt_ns')==prior['last_good_receipt_ns']
 return current.get('status')=='observed' and not current.get('held') and current.get('records')==int(expected)
def command():
 global NEGATIVE_OVERRIDE,STEP,OBSERVATION_ERROR
 p=profile();mode=sys.argv[2];out={}
 if mode in ('batch','negatives'):
  previous=sys.argv[:];results=[]
  if mode=='batch':operations=json.loads(sys.argv[3])
  else:operations=[['negative'] for _ in json.loads(read('/input/negative'))[p['role']]]
  cases=json.loads(read('/input/negative')).get(p['role'],[]) if mode=='negatives' else []
  for index,operation in enumerate(operations):
   if mode=='negatives':NEGATIVE_OVERRIDE=cases[index]
   capture=io.StringIO();stdout=sys.stdout;sys.stdout=capture;sys.argv=['/actor.py','command',*map(str,operation)]
   try:command()
   finally:sys.stdout=stdout;sys.argv=previous
   results.append(json.loads(capture.getvalue()))
   if mode=='negatives' and p['role']=='producer':
    capture=io.StringIO();sys.stdout=capture;sys.argv=['/actor.py','command','append']
    try:command()
    finally:sys.stdout=stdout;sys.argv=previous
    assert json.loads(capture.getvalue())['exact_original_ack'];results[-1]['same_append_liveness']=True
   if mode=='negatives' and p['role']=='health':
    assert not health(p)['held'];results[-1]['same_health_liveness']=True
  NEGATIVE_OVERRIDE=None;print(json.dumps({'results':results}));return
 if mode=='identity':out={'identity':identity(),'pid1_identity':identity(1)}
 elif mode=='barrier':
  generation=int(sys.argv[3]);end=time.monotonic()+5
  while True:
   try:out=json.loads(read(PRIVATE/'status'))
   except FileNotFoundError:out={}
   if out.get('generation')==generation:break
   if time.monotonic()>end:raise RuntimeError('phase_barrier_deadline')
   time.sleep(.03)
 elif mode=='state':
  value=json.loads(read(PRIVATE/'outbox/state'));out={'state':value}
  pending=PRIVATE/'outbox/pending'
  if pending.exists():out['pending']=base64.b64encode(read(pending,4096)).decode()
 elif mode=='observe':
  expected=sys.argv[3];end=time.monotonic()+3
  try:prior=json.loads(read(PRIVATE/'health'))
  except FileNotFoundError:prior={}
  after=time.monotonic_ns()
  while True:
   try:out=json.loads(read(PRIVATE/'health'))
   except FileNotFoundError:out={}
   if fresh_observation(out,prior,after,expected):break
   if time.monotonic()>end:
    OBSERVATION_ERROR={'observation_deadline':True,'expected_unavailable':expected=='unavailable','fresh':out.get('monotonic_ns',0)>after,'last_good_unchanged':out.get('last_good_receipt_ns')==prior.get('last_good_receipt_ns'),'status':out.get('status') if out.get('status') in ('observed','unavailable') else 'absent','observations':out.get('observations',0)};raise RuntimeError('fresh_health_deadline')
   time.sleep(.03)
 elif mode in ('ready','persisted','ingest','query','outage-query'):
  c=context(p,'append');end=time.monotonic()+5
  if mode=='ingest':
   event={'schema_version':1,'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),'source':{'type':'application'},'severity':'info','message':p['canary'],'attributes':{'private':p['attribute_canary']}}
   code,raw,h=request(c,'monolith',8080,'/v1/events',p['api_token'],'POST',json.dumps(event).encode());assert code==202;out={'accepted':True}
  elif mode in ('query','outage-query'):
   code,raw,h=request(c,'monolith',8080,'/v1/events',p['api_token']);present=p['canary'].encode() in raw
   if mode=='query':assert code==200 and present;out={'private_result':True}
   else:
    assert code==503 and not present and p['attribute_canary'].encode() not in raw and h.get('cache-control')=='no-store'
    assert request(c,'monolith',8080,'/readyz',p['api_token'])[0]==503;out={'failed_closed':True,'readiness_unavailable':True}
  else:
   while True:
    try:
     code,raw,h=request(c,'monolith',8080,'/readyz' if mode=='ready' else '/metrics',p['api_token'])
     ok=code==200 and (mode=='ready' or any(line.startswith(b'signal_storage_persisted_total ') and int(line.split()[1])==1 for line in raw.splitlines()))
     if ok:out={'ready':True};break
    except (OSError,http.client.HTTPException):pass
    if time.monotonic()>end:raise RuntimeError('native_ready_or_persistence_deadline')
    time.sleep(.03)
 elif mode=='append':
  path=PRIVATE/'original'
  if not path.exists():
   record={'schema_version':1,'record_id':str(uuid.uuid4()),'producer_id':p['producer_id'],'sequence':1,'timestamp':'2026-10-09T12:00:00Z','actor':{'kind':'system'},'action':{'kind':'configuration_activation','configuration':'runtime','revision_sha256':'b'*64}}
   path.write_bytes(json.dumps(record,indent=2).encode());path.chmod(0o600)
  raw=read(path,4096);record=json.loads(raw);code,reply,h=request(context(p,'append'),'receiver',8081,'/v1/audit/records',p['token'],'POST',raw,1024)
  expected={k:record[k] for k in ['schema_version','record_id','producer_id','sequence']};expected['body_sha256']=hashlib.sha256(raw).hexdigest()
  assert code==200 and json.loads(reply)==expected and h.get('cache-control')=='no-store'
  out={'exact_original_ack':True}
 elif mode=='negative':
  negative=NEGATIVE_OVERRIDE if NEGATIVE_OVERRIDE is not None else json.loads(read('/input/negative'));case=negative['case'];raw=read(PRIVATE/'original',4096) if (PRIVATE/'original').exists() else b'{}'
  STEP=case
  health_target=case in ('append_identity_health','wrong_health_credential')
  c=context(p,'health' if health_target else 'append',case!='missing_certificate');token=negative.get('token',p['token'])
  if case=='other_namespace':
   body=json.loads(raw);body['producer_id']=negative['producer_id'];raw=json.dumps(body).encode()
  try:
   code,reply,h=request(c,'receiver',8082 if health_target else 8081,'/v1/audit/health' if health_target else '/v1/audit/records',token,'GET' if health_target else 'POST',None if health_target else raw,1024,tls_probe=case in ('append_identity_health','health_identity_append','missing_certificate'))
   assert case in ('wrong_credential','ordinary_credential','other_namespace','wrong_health_credential') and code==403 and h.get('cache-control')=='no-store';out={'denial':'authenticated_http403'}
  except ssl.SSLError as e:
   assert case in ('append_identity_health','health_identity_append','missing_certificate') and e.reason in ('TLSV1_ALERT_UNKNOWN_CA','SSLV3_ALERT_BAD_CERTIFICATE','TLSV13_ALERT_CERTIFICATE_REQUIRED','TLSV1_ALERT_DECRYPT_ERROR','SSLV3_ALERT_CERTIFICATE_UNKNOWN');out={'denial':'tls_certificate_rejected'}
 elif mode=='log':out={'log':base64.b64encode(read(PRIVATE/'monolith.log',65536)).decode()}
 elif mode=='confinement':
  out={'receiver_paths_absent':all(not pathlib.Path(path).exists() for path in ['/restricted/root','/restricted/config','/restricted/key','/restricted/secret']), 'own_private_mode':PRIVATE.stat().st_mode&0o777}
 else:raise RuntimeError('unsupported_fixture_command')
 print(json.dumps(out))
try:
 if sys.argv[1]=='pid1':pid1(ROLE)
 else:command()
except BaseException as error:
 print(json.dumps(dict({'fixture_error':type(error).__name__,'fixture_phase':STEP,'errno':getattr(error,'errno',None)},**globals().get('OBSERVATION_ERROR',{}))));raise SystemExit(1)
'''

def strict_json(raw):
    def pairs(values):
        result={}
        for key,value in values:
            if key in result:raise RuntimeError('record_duplicate_field')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs)

def valid_uuid(value):
    try:return isinstance(value,str) and str(uuid.UUID(value))==value and uuid.UUID(value).int!=0
    except (ValueError,AttributeError,TypeError):return False

def validate_record(record):
    if set(record)!={'schema_version','record_id','producer_id','sequence','timestamp','actor','action'} or type(record['schema_version']) is not int or record['schema_version']!=1 or type(record['sequence']) is not int or not 1<=record['sequence']<=18446744073709551615 or not valid_uuid(record['record_id']) or not valid_uuid(record['producer_id']):raise RuntimeError('record_integer_identity_shape')
    if not isinstance(record['timestamp'],str):raise RuntimeError('record_time_shape')
    timestamp=datetime.datetime.fromisoformat(record['timestamp'].replace('Z','+00:00'))
    if timestamp.tzinfo is None or timestamp.utcoffset()!=datetime.timedelta(0) or timestamp.year<1970:raise RuntimeError('record_time_shape')
    if record['actor'] not in ({'kind':'system'},{'kind':'bootstrap'}):raise RuntimeError('record_fixture_actor_shape')
    action=record['action'];kind=action.get('kind') if isinstance(action,dict) else None
    if kind=='configuration_activation':
        if set(action)!={'kind','configuration','revision_sha256'} or action['configuration'] not in ['runtime','rules'] or not isinstance(action['revision_sha256'],str) or len(action['revision_sha256'])!=64 or any(c not in '0123456789abcdef' for c in action['revision_sha256']):raise RuntimeError('record_activation_shape')
    elif kind in ('access_decision','operation_completion'):
        outcome='decision' if kind=='access_decision' else 'completion'
        if set(action)!={'kind','operation','operation_id',outcome} or action['operation']!='query_events' or not valid_uuid(action['operation_id']) or action[outcome] not in (['granted','denied','unavailable'] if outcome=='decision' else ['success','denied','failed','uncertain']):raise RuntimeError('record_query_action_shape')
    else:raise RuntimeError('record_fixture_action_shape')

def query_pair(rows):
    if len(rows)!=2:return False
    first,last=[r['record'] for r in rows];operation=first['action'].get('operation_id')
    return first['actor']==last['actor']=={'kind':'bootstrap'} and first['producer_id']==last['producer_id'] and last['sequence']==first['sequence']+1 and first['record_id']!=last['record_id'] and valid_uuid(operation) and first['action']=={'kind':'access_decision','operation':'query_events','operation_id':operation,'decision':'granted'} and last['action']=={'kind':'operation_completion','operation':'query_events','operation_id':operation,'completion':'success'}

def journal(path):
    raw=bytearray(); DAC.consume_regular(path,131072,raw.extend)
    identity=bytearray();DAC.consume_regular(path.with_name('control'),32,identity.extend)
    if len(identity)!=32 or identity[:8]!=b'SIGAUD01' or not uuid.UUID(bytes=bytes(identity[8:24])).int or identity[24:]!=b'\0'*8:raise RuntimeError('journal_control_shape')
    pos=0;rows=[];sequences={};ids=set()
    while pos<len(raw):
        if len(rows)>=64 or raw[pos:pos+4]!=b'AUD1' or pos+72>len(raw): raise RuntimeError('journal_shape_capacity')
        length=struct.unpack_from('<I',raw,pos+4)[0]
        if not 0<length<=4096 or pos+72+length>len(raw): raise RuntimeError('journal_body_capacity')
        header=bytes(raw[pos:pos+72]);original=bytes(raw[pos+72:pos+72+length])
        if hashlib.sha256(b'platform-signal/audit-receiver-header/v1\0'+identity+header[:40]).digest()!=header[40:] or hashlib.sha256(b'platform-signal/audit-receiver-frame/v1\0'+identity+original).digest()!=header[8:40]:raise RuntimeError('journal_control_checksum_binding')
        record=strict_json(original);validate_record(record)
        if record['record_id'] in ids or record['sequence']!=sequences.get(record['producer_id'],0)+1:raise RuntimeError('journal_sequence_unique_identity')
        sequences[record['producer_id']]=record['sequence'];ids.add(record['record_id']);rows.append({'original':original,'record':record});pos+=72+length
    return rows

class Campaign(DAC.Bounded):
    def __init__(self):
        super().__init__();self.network='signal-roles-'+self.owner[:12];self.network_reserved=False;self.preparation_commands=0;self.actor_errors=[]
    def docker(self,*args,cleanup=False,limit=1048576):
        if self.commands+self.preparation_commands>=64:raise RuntimeError('original_docker_command_capacity')
        reserved=2*len(self.names)+(2 if self.network_reserved else 0)
        if not cleanup and self.commands+self.preparation_commands+1+reserved>64:raise RuntimeError('owned_cleanup_command_reserve')
        return super().docker(*args,cleanup=cleanup,limit=limit)
    def cleanup(self):
        super().cleanup()
        if self.network_reserved:
            try:
                code,raw=self.docker('network','inspect','--format','{"labels":{{json .Labels}},"internal":{{json .Internal}}}',self.network,cleanup=True,limit=65536)
                value=json.loads(raw) if not code else {}
                if code or value.get('labels',{}).get(DAC.LABEL)!=self.owner or value.get('internal') is not True:self.cleanup_errors.append('network_owner_uncertain');return
                code,_=self.docker('network','rm',self.network,cleanup=True)
                if code:self.cleanup_errors.append('network_removal_uncertain')
                else:self.network_reserved=False
            except Exception:self.cleanup_errors.append('network_cleanup_uncertain')
    def container(self,role,pair,image,mounts,entrypoint,args,env=(),private_size='2m',memory='128m',network=True):
        name='signal-roles-'+self.owner[:12]+'-'+role;self.names.append(name)
        bindings=[]
        for source,target,readonly in mounts:bindings+=['--mount',f'type=bind,src={source},dst={target}'+(',readonly' if readonly else '')]
        command=['create','--pull=never','--name',name,'--label',DAC.LABEL+'='+self.owner,'--user',f'{pair[0]}:{pair[1]}','--read-only','--cap-drop=ALL','--security-opt','no-new-privileges','--no-healthcheck','--memory',memory,'--pids-limit=64','--cpus=1','--network',self.network if network else 'none','--tmpfs',f'/private:rw,noexec,nosuid,size={private_size},uid={pair[0]},gid={pair[1]},mode=0700','--entrypoint',entrypoint]
        if network:command+=['--network-alias',role]
        code,_=self.docker(*command,*env,*bindings,image,*args)
        if code:raise RuntimeError('owned_role_create_failed')
        return name
    def actor(self,name,*args):
        code,raw=self.docker('exec',name,'python3','-B','/actor.py','command',*map(str,args),limit=65536)
        if code:
            try:
                value=json.loads(raw);kind=value.get('fixture_error');actor_phase=value.get('fixture_phase');error_number=value.get('errno')
                allowed=['AssertionError','RuntimeError','FileNotFoundError','SSLError','ValueError','BrokenPipeError','RemoteDisconnected','PermissionError','ConnectionResetError','KeyError','TypeError','NameError','UnboundLocalError']
                kind=kind if kind in allowed else 'unrecognized_error'
                phases=['actor_setup','private_profile_copy','monolith_private_layout','native_monolith_spawn','native_identity_read','wrong_credential','ordinary_credential','other_namespace','missing_certificate','append_identity_health','health_identity_append','wrong_health_credential']
                self.actor_errors.append({'command':str(args[0]),'kind':kind,'phase':actor_phase if actor_phase in phases else 'unrecognized_phase','errno':error_number if type(error_number) is int else None})
                if value.get('observation_deadline') is True:self.actor_errors[-1]['observation']={k:value[k] for k in ['expected_unavailable','fresh','last_good_unchanged','status','observations']}
            except Exception:kind='unrecognized_error'
            raise RuntimeError('actor_'+str(args[0])+'_'+kind)
        return json.loads(raw)
    def batch(self,name,operations):return self.actor(name,'batch',json.dumps(operations))['results']

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);args=p.parse_args()
    os.umask(0o077);args.output.mkdir(parents=True,exist_ok=False,mode=0o700)
    run=Campaign();prep=DAC.Bounded();private=pathlib.Path(tempfile.mkdtemp(prefix='signal-role-composition-'));started=time.monotonic();checks=[];phase='preparation';failure=None
    source_paths=[pathlib.Path(__file__),ROOT/'scripts/test-audit-role-composition.py',ROOT/'scripts/check-audit-receiver-permissions.py',ROOT/'tests/integration/transport-server-process.py',ROOT/'scripts/check-access-idp.py',ROOT/'scripts/check-native-qualification.py',ROOT/'benchmarks/pipeline.py',ROOT/'tests/integration/access-server-process.py',DAC.BINARY.with_name('binary.json'),ROOT/'rules/examples/login-failure.yaml']
    before={str(x.relative_to(ROOT)):DAC.digest(x) for x in source_paths}
    libs={};roles={};rows=[];health_samples=0;generation=0;markers=[];setup=None
    def check(name,value):
        nonlocal phase
        phase=name
        if not value:raise AssertionError(name)
        checks.append({'name':name,'status':'passed'})
    def interrupt(*_):raise RuntimeError('owned_interruption')
    old={s:signal.signal(s,interrupt) for s in [signal.SIGTERM,signal.SIGINT]}
    try:
        check('immutable-accepted-native-pin',DAC.digest(DAC.BINARY,DAC.BINARY_FILE_CAP)==DAC.PIN and DAC.digest(PROBE)==PROBE_PIN)
        provenance=DAC.read_provenance(DAC.BINARY.with_name('binary.json'))
        identities=DAC.role_identities(os.getuid(),os.getgid());pairs=dict(zip(['receiver','monolith','producer','health'],identities))
        for image in [DAC.IMAGE,NODE,PYTHON]:
            code,raw=run.docker('image','inspect',image,'--format','{{json .Id}} {{json .Os}} {{json .Architecture}}',limit=65536)
            check('cached-native-image-'+str(len(checks)),code==0 and raw.decode().strip()==f'"{image}" "linux" "amd64"')
        runtime=private/'runtime';runtime.mkdir(mode=0o755)
        supplier=run.container('runtime-copy',pairs['receiver'],DAC.IMAGE,[], '/not-started',[],network=False)
        for name in ['libc.so.6','libm.so.6','libgcc_s.so.1','ld-linux-x86-64.so.2']:
            code,_=run.docker('cp','-L',supplier+':/lib/x86_64-linux-gnu/'+name,str(runtime/name),limit=RUNTIME_CAP)
            check('bounded-native-runtime-copy-'+name,code==0);(runtime/name).chmod(0o555 if name=='ld-linux-x86-64.so.2' else 0o444);libs[name]=DAC.digest(runtime/name,RUNTIME_CAP)
        runtime.chmod(0o555)
        check('public-native-runtime-traversable',runtime.stat().st_mode&0o777==0o555)
        # Public runtime transfer, never app diagnostics; exact owned supplier is retired before roles.
        code,_=run.docker('rm',supplier);check('owned-runtime-supplier-retired',code==0);run.names.remove(supplier)
        actor=private/'actor.py';actor.write_text(ACTOR);actor.chmod(0o444)
        control=private/'control';control.write_text(json.dumps({'generation':0,'action':'bootstrap'}));control.chmod(0o604)
        negative=private/'negative';negative.write_text('{}');negative.chmod(0o604)
        spec=importlib.util.spec_from_file_location('role_transport',ROOT/'tests/integration/transport-server-process.py');transport=importlib.util.module_from_spec(spec);spec.loader.exec_module(transport)
        certs=object.__new__(transport.Run);certs.private=private
        def openssl(*values):
            code,_=prep.command(['openssl',*map(str,values)],limit=65536)
            if code:raise RuntimeError('certificate_preparation_failed')
        certs.openssl=openssl
        def leaf(ca,name,usage,hostname):
            prefix=ca/name;certs.openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-noenc','-keyout',prefix.with_suffix('.key'),'-out',prefix.with_suffix('.csr'),'-subj','/CN=synthetic-'+name)
            ext=prefix.with_suffix('.ext');ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage='+usage+'\nsubjectAltName=DNS:'+hostname+'\n')
            certs.openssl('ca','-batch','-config',ca/'ca.conf','-in',prefix.with_suffix('.csr'),'-out',prefix.with_suffix('.pem'),'-notext','-extfile',ext)
            certs.openssl('pkcs8','-topk8','-nocrypt','-in',prefix.with_suffix('.key'),'-outform','DER','-out',prefix.with_suffix('.der-key'));return prefix
        append_ca=certs.ca('append');health_ca=certs.ca('health')
        append_server=leaf(append_ca,'receiver','serverAuth','receiver');api_server=leaf(append_ca,'monolith','serverAuth','monolith')
        mono_client=leaf(append_ca,'monolith-client','clientAuth','monolith');producer_client=leaf(append_ca,'producer-client','clientAuth','producer');health_server=leaf(health_ca,'health-server','serverAuth','receiver');health_client=leaf(health_ca,'health-client','clientAuth','health')
        def material(name,cert,roots):return json.loads(certs.material(name,cert,roots).read_text())
        tokens={name:'synthetic-role-'+uuid.uuid4().hex for name in ['monolith','producer','health','api']};markers=[value.encode() for value in tokens.values()]
        p_id=str(uuid.uuid4());canary='synthetic-role-private-event-canary';attribute='synthetic-role-private-attribute-canary';markers += [canary.encode(),attribute.encode()]
        common={'append_ca':(append_ca/'ca.pem').read_text(),'health_ca':(health_ca/'ca.pem').read_text()}
        profiles={
            'monolith':dict(common,token=tokens['monolith'],api_token=tokens['api'],audit_tls=material('audit-tls',mono_client,[append_ca]),api_tls=material('api-tls',api_server,[append_ca]),audit={'schema_version':1,'operations':['query_events'],'endpoint':'https://receiver:8081/v1/audit/records','tls_config':'/private/audit-tls','outbox_directory':'/private/outbox','connect_timeout_ms':300},rule=(ROOT/'rules/examples/login-failure.yaml').read_text()),
            'producer':dict(common,token=tokens['producer'],api_token=tokens['api'],producer_id=p_id,canary=canary,attribute_canary=attribute),
            'health':dict(common,token=tokens['health'])}
        for role,cert in [('monolith',mono_client),('producer',producer_client),('health',health_client)]:
            profiles[role]['role']=role
            profiles[role]['client.pem']=cert.with_suffix('.pem').read_text();profiles[role]['client.key']=cert.with_suffix('.key').read_text()
            path=private/(role+'-profile');path.write_text(json.dumps(profiles[role]));path.chmod(0o404)
        # Public cached-runtime transfer owns no live resources now. Runtime
        # accounting is separate, but retains the original absolute deadline and
        # a shared64 Docker-command cap including that preparation.
        setup=run;run=Campaign();run.deadline=setup.deadline;run.preparation_commands=setup.commands
        run.network_reserved=True;code,_=run.docker('network','create','--internal','--label',DAC.LABEL+'='+run.owner,run.network);check('owned-internal-network',code==0)
        for role,image in [('monolith',NODE),('producer',PYTHON)]:
            mounts=[(actor,'/actor.py',True),(private/(role+'-profile'),'/input/profile',True),(negative,'/input/negative',True)]
            if role=='monolith':mounts += [(control,'/input/control',True),(runtime,'/native',True),(DAC.BINARY,'/server',True)]
            roles[role]=run.container(role,pairs[role],image,mounts,'python3',['-B','/actor.py','pid1',role],private_size='128m' if role=='monolith' else '2m',memory='768m' if role=='monolith' else '128m')
        code,_=run.docker('start',roles['monolith'],roles['producer']);check('monolith-producer-owned-start',code==0)
        def phase_change(action,extra=None):
            nonlocal generation
            generation+=1;control.write_text(json.dumps({'generation':generation,'action':action}))
            results=run.batch(roles['monolith'],[['barrier',generation]]+([extra] if extra else []));result=results[0]
            check('monolith-phase-'+action,DAC.valid_identity(result['identity'],*pairs['monolith']) and DAC.valid_identity(result['pid1_identity'],*pairs['monolith']))
            if action in ('active','bootstrap'):check('actual-native-monolith-identity',DAC.valid_identity(result['native_identity'],*pairs['monolith']))
            return (result,results[1]) if extra else result
        run.actor(roles['producer'],'ready');_,state=phase_change('stop',['state'])
        actual=state['state'];m_id=actual['producer_id'];check('trusted-actual-outbox-enrollment',str(uuid.UUID(m_id))==m_id and actual['schema_version']==1 and actual['acknowledged'] is None and 'pending' not in state)
        receipts=private/'receipts';receipts.mkdir(mode=0o700)
        key=private/'receiver-key';key.write_text(json.dumps(material('receiver-tls',append_server,[append_ca])))
        health_tls=private/'receiver-health';health_tls.write_text(json.dumps(material('health-tls',health_server,[health_ca])))
        secret=private/'receiver-secret';secret.write_text(tokens['health'])
        env=private/'receiver-env';env.write_text('ROLE_MONOLITH='+tokens['monolith']+'\nROLE_PRODUCER='+tokens['producer']+'\nROLE_HEALTH='+tokens['health']+'\n')
        config=private/'receiver-config';config.write_text(json.dumps({'schema_version':1,'directory':'/restricted/root','append':{'listen':'0.0.0.0:8081','tls_config':'/restricted/key','max_connections':4},'health':{'listen':'0.0.0.0:8082','tls_config':'/restricted/health-tls','max_connections':2},'producers':[{'producer_id':m_id,'credential_env':'ROLE_MONOLITH'},{'producer_id':p_id,'credential_env':'ROLE_PRODUCER'}],'health_credential_env':'ROLE_HEALTH','max_bytes':131072,'max_records':64,'request_timeout_ms':700,'header_timeout_ms':700,'connection_timeout_ms':1500,'shutdown_timeout_ms':1000}))
        rmounts=[(DAC.BINARY,'/server',True),(PROBE,'/probe',True),(receipts,'/restricted/root',False),(config,'/restricted/config',True),(key,'/restricted/key',True),(health_tls,'/restricted/health-tls',True),(secret,'/restricted/secret',True)]
        init=run.container('initialize',pairs['receiver'],DAC.IMAGE,rmounts,'/server',['--initialize-audit-receiver','--config','/restricted/config'],env=['--env-file',str(env)])
        code,_=run.docker('start','-a',init);check('actual-fixed-enrollment-initialize',code==0);code,_=run.docker('rm',init);check('owned-initializer-retired',code==0);run.names.remove(init)
        roles['receiver']=run.container('receiver',pairs['receiver'],DAC.IMAGE,rmounts,'/server',['--audit-receiver','--config','/restricted/config'],env=['--env-file',str(env)],memory='256m')
        roles['health']=run.container('health',pairs['health'],PYTHON,[(actor,'/actor.py',True),(private/'health-profile','/input/profile',True),(negative,'/input/negative',True)],'python3',['-B','/actor.py','pid1','health'])
        code,_=run.docker('start',roles['receiver'],roles['health']);check('actual-receiver-independent-health-owner-start',code==0)
        inspection='{"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"drop":{{json .HostConfig.CapDrop}},"add":{{json .HostConfig.CapAdd}},"groups":{{json .HostConfig.GroupAdd}},"security":{{json .HostConfig.SecurityOpt}},"network":{{json .HostConfig.NetworkMode}},"pids":{{json .HostConfig.PidsLimit}},"cpus":{{json .HostConfig.NanoCpus}},"mounts":[{{range $i,$m:=.Mounts}}{{if $i}},{{end}}{{json $m.Destination}}{{end}}]}'
        code,raw=run.docker('inspect','--format',inspection,*[roles[r] for r in ['monolith','producer','receiver','health']],limit=65536)
        configured=[json.loads(line) for line in raw.splitlines()];check('actual-four-role-container-fences',code==0 and len(configured)==4 and all(v['user']==f'{pairs[r][0]}:{pairs[r][1]}' and v['readonly'] is True and v['privileged'] is False and v['drop']==['ALL'] and not v['add'] and not v['groups'] and v['security']==['no-new-privileges'] and v['network']==run.network and v['pids']==64 and v['cpus']==1000000000 and all(target in ['/actor.py','/input/profile','/input/negative','/input/control','/native','/server','/probe','/restricted/root','/restricted/config','/restricted/key','/restricted/health-tls','/restricted/secret','/private'] for target in v['mounts']) for r,v in zip(['monolith','producer','receiver','health'],configured)))
        def observe(count):
            nonlocal health_samples
            result=run.actor(roles['health'],'observe',count);health_samples=result['observations'];check('fresh-independent-health-'+str(count),True)
        observe(0)
        run.actor(roles['producer'],'append');check('separately-enrolled-exact-original-ack',len(journal(receipts/'journal'))==1)
        for role in ['monolith','producer','health']:
            result,confinement=run.batch(roles[role],[['identity'],['confinement']]);check(role+'-actual-identities',DAC.valid_identity(result['identity'],*pairs[role]) and DAC.valid_identity(result['pid1_identity'],*pairs[role]))
            check(role+'-normal-receiver-path-confinement',confinement=={'receiver_paths_absent':True,'own_private_mode':0o700})
        code,raw=run.docker('exec',roles['receiver'],'/probe','owner',limit=65536);ridentity=json.loads(raw);check('actual-receiver-pid1-identity',code==0 and DAC.valid_identity(ridentity['pid1_identity'],*pairs['receiver']))
        baseline=DAC.private_snapshot(receipts)
        cases=[('producer','wrong_credential','synthetic-wrong'),('producer','ordinary_credential',tokens['api']),('producer','other_namespace',tokens['producer']),('producer','missing_certificate',tokens['producer']),('producer','append_identity_health',tokens['health']),('monolith','append_identity_health',tokens['health']),('health','health_identity_append',tokens['health']),('health','health_identity_append',tokens['producer']),('health','wrong_health_credential',tokens['producer'])]
        negative.write_text(json.dumps({role:[{'case':case,'token':token,'producer_id':m_id} for owner,case,token in cases if owner==role] for role in ['producer','monolith','health']}))
        for role in ['producer','monolith','health']:
            results=run.actor(roles[role],'negatives')['results'];selected=[case for owner,case,_ in cases if owner==role]
            check(role+'-actual-cross-role-denials',len(results)==len(selected) and all(r['denial'] in ('authenticated_http403','tls_certificate_rejected') for r in results) and DAC.private_snapshot(receipts)==baseline)
        negative.write_text('{}');check('same-listener-liveness-with-no-history-effects',DAC.private_snapshot(receipts)==baseline)
        phase_change('active');observe(3);observed=journal(receipts/'journal');observed_m=[r for r in observed if r['record']['producer_id']==m_id];run.actor(roles['producer'],'ready');check('activation-receipts-observed-then-readiness-checked',len(observed)==3 and len(observed_m)==2 and [r['record']['action']['configuration'] for r in observed_m]==['runtime','rules'] and all(r['record']['actor']=={'kind':'system'} for r in observed_m))
        run.batch(roles['producer'],[['ingest'],['persisted'],['query']]);observe(5)
        initial=journal(receipts/'journal');initial_m=[r for r in initial if r['record']['producer_id']==m_id];check('initial-native-granted-success-query-pair',len(initial)==5 and query_pair(initial_m[-2:]))
        original=DAC.digest(receipts/'journal');result=phase_change('kill');check('actual-monolith-sigkill',result['last_exit']==-signal.SIGKILL and DAC.digest(receipts/'journal')==original);observe(5)
        phase_change('active');observe(7);run.actor(roles['producer'],'ready')
        code,_=run.docker('stop','-t','2',roles['receiver']);check('owned-receiver-outage',code==0);observe('unavailable')
        run.actor(roles['producer'],'outage-query');_,pending=phase_change('stop',['state']);original_pending=base64.b64decode(pending['pending']);pending_record=json.loads(original_pending);check('native-outage-actual-pending',pending_record['producer_id']==m_id and pending_record['sequence']==7 and pending_record['action']['kind']=='access_decision')
        code,_=run.docker('start',roles['receiver']);check('actual-existing-receiver-restart',code==0);observe(7);phase_change('active');observe(10);rows=journal(receipts/'journal');m_rows=[r for r in rows if r['record']['producer_id']==m_id]
        check('exact-original-native-pending-replay',m_rows[6]['original']==original_pending and [r['record']['action']['configuration'] for r in m_rows[7:]]==['runtime','rules']);run.batch(roles['producer'],[['ready'],['query']]);observe(12);rows=journal(receipts/'journal');m_rows=[r for r in rows if r['record']['producer_id']==m_id]
        check('fresh-native-granted-success-query-not-old-ack',query_pair(m_rows[-2:]) and m_rows[-2]['record']['action']['operation_id']!=pending_record['action']['operation_id'])
        check('exact-independent-producer-history',len(rows)==12 and [r['record']['sequence'] for r in m_rows]==list(range(1,12)) and len({r['record']['record_id'] for r in rows})==12)
        check('receipts-exclude-private-data',all(not any(marker in row['original'] for marker in markers) for row in rows))
        _,log_result=phase_change('stop',['log']);observe(12)
        code,_=run.docker('stop','-t','2',roles['receiver']);check('final-receiver-stopped-before-witness-copy',code==0)
        witness=args.output/'private-witnesses';witness.mkdir(mode=0o700)
        for name in ['control','journal']:
            raw=bytearray();DAC.consume_regular(receipts/name,131072 if name=='journal' else 32,raw.extend);(witness/name).write_bytes(raw)
        (witness/'original-pending').write_bytes(original_pending)
        final_rows=journal(witness/'journal');check('complete-stopped-control-journal-pending-witnesses',len(final_rows)==12 and final_rows==rows and final_rows[7]['original']==original_pending)
        log=base64.b64decode(log_result['log']);markers += [m_id.encode(),p_id.encode(),profiles['monolith']['rule'].encode(),b'/private/audit.json',b'/private/audit-tls',b'/private/api-tls']+[r['record']['record_id'].encode() for r in rows]+[r['record']['action'].get('operation_id','').encode() for r in rows if r['record']['action'].get('operation_id')]+[r['record']['action'].get('revision_sha256','').encode() for r in rows if r['record']['action'].get('revision_sha256')]
        check('monolith-ordinary-log-privacy',not any(marker in log for marker in markers));(args.output/'monolith.log').write_bytes(log)
    except BaseException as error:
        allowed_kinds=['AssertionError','RuntimeError','OSError','FileNotFoundError','PermissionError','ValueError','KeyError','TypeError','JSONDecodeError','TimeoutError','ChildProcessError','KeyboardInterrupt','InterruptedError']
        failure={'kind':type(error).__name__ if type(error).__name__ in allowed_kinds else 'OtherFixtureError','phase':phase,'oracle':'fixture_command_failed' if isinstance(error,RuntimeError) else 'fixture_assertion_failed' if isinstance(error,AssertionError) else 'typed_fixture_failure'}
        if 'monolith' in roles:
            try:
                value=run.actor(roles['monolith'],'log');log=base64.b64decode(value['log']);(args.output/'failed-monolith.log').write_bytes(log)
                failure['bounded_private_log_retained']=True
            except Exception:failure['bounded_private_log_retained']=False
            try:
                code,raw=run.docker('logs','--tail','8',roles['monolith'],limit=65536)
                if not code:
                    (args.output/'failed-supervisor.log').write_bytes(raw)
                    failure['bounded_supervisor_log_retained']=True
            except Exception:failure['bounded_supervisor_log_retained']=False
    finally:
        for s in old:signal.signal(s,signal.SIG_IGN)
        run.cleanup();prep.cleanup()
        if setup is not None:setup.cleanup()
        if not run.cleanup_errors and not prep.cleanup_errors and (setup is None or not setup.cleanup_errors):
            if 'runtime' in locals():runtime.chmod(0o700)
            shutil.rmtree(private)
        for s,h in old.items():signal.signal(s,h)
    try:guards=before=={str(x.relative_to(ROOT)):DAC.digest(x) for x in source_paths} and DAC.digest(DAC.BINARY,DAC.BINARY_FILE_CAP)==DAC.PIN and DAC.digest(PROBE)==PROBE_PIN
    except Exception:guards=False
    report={'schema_version':1,'status':'passed_simulated' if failure is None and not run.cleanup_errors and not prep.cleanup_errors and (setup is None or not setup.cleanup_errors) and guards else 'failed','scope':'actual local LinuxAMD64 four distinct nonzero-UID debug receiver/native monolith/producer/health composition; accepted de8 semantics only','failure':failure,'actor_errors':run.actor_errors,'checks':checks,'passed_check_count':len(checks),'receipt_count':len(rows),'health_observation_count':health_samples,'source_sha256':before,'binary_sha256':DAC.PIN,'source_commit':DAC.ACCEPTED_COMMIT,'images':{'receiver':DAC.IMAGE,'monolith_supervisor':NODE,'client_health':PYTHON},'public_native_runtime_sha256':libs,'roles':{r:{'uid':pair[0],'gid':pair[1]} for r,pair in pairs.items()} if 'pairs' in locals() else {},'elapsed_seconds':time.monotonic()-started,'docker_command_count':run.commands+(setup.commands if setup else 0),'runtime_command_count':run.commands,'public_runtime_preparation_count':setup.commands if setup else 0,'certificate_command_count':prep.commands,'cleanup_errors':run.cleanup_errors+prep.cleanup_errors+(setup.cleanup_errors if setup else []),'input_guards_match':guards,'private_recovery_required':bool(run.cleanup_errors or prep.cleanup_errors or (setup is not None and setup.cleanup_errors)),'limitations':['Synthetic local credentials/PKI and Docker nonzeroUID restriction; daemon/admin/kernel trusted, no actual production IAM/separate hostusers/encryption/cloud/nativeARM/liveIdP.','No current health SDK/client or release-image/current workspace qualification.','Temporary operator credential injection is explicitly negative-test only; normal role profiles contain only own application credentials.','Private command captures are transient; public report contains no credentials, private keys, actor/record/producer IDs or raw receipt bodies.']}
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['status','passed_check_count','receipt_count','failure','cleanup_errors','input_guards_match','elapsed_seconds']}));return 0 if report['status']=='passed_simulated' else 1

if __name__=='__main__':raise SystemExit(main())

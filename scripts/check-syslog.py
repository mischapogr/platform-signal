#!/usr/bin/env python3
"""Actual owned site syslog/mTLS/spool/outage qualification; synthetic devices."""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse
import zlib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('syslog_tls_fixture', ROOT / 'tests/integration/transport-server-process.py')
TLS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TLS)

def run(agent, server, output):
    fixture = TLS.Run(server, agent, output)
    processes, logs, checks = [], [], []
    environment = {k:v for k,v in os.environ.items() if not k.startswith('SIGNAL_')}
    token = 'synthetic-syslog-token'
    def port():
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));return s.getsockname()[1]
    def wait(predicate, label, seconds=8):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            if predicate():return
            time.sleep(.025)
        raise AssertionError(label)
    def request(p,path):
        c=http.client.HTTPConnection('127.0.0.1',p,timeout=1)
        try:
            c.request('GET',path,headers={'Authorization':'Bearer '+token})
            r=c.getresponse();body=r.read(262145);assert len(body)<=262144 and r.status==200
            return body
        finally:c.close()
    def metrics(p):
        try:return {l.split()[0]:float(l.split()[1]) for l in request(p,'/metrics').decode().splitlines() if l and not l.startswith('#')}
        except (OSError,http.client.HTTPException):return {}
    def start(name,args,env):
        path=output/(name+'.log');logs.append(path)
        with path.open('wb') as log:p=subprocess.Popen(args,cwd=ROOT,env=env,stdout=log,stderr=log)
        processes.append(p);return p
    def kill(p):
        assert p.poll() is None;p.kill();assert p.wait(timeout=5)==-signal.SIGKILL
    def rows(p,source):return json.loads(request(p,'/v1/events?'+urllib.parse.urlencode({'source_name':source,'limit':100})))['events']
    def ready(p,listener):
        wait(lambda: p.poll() is None and bool(metrics(listener)), 'agent metrics startup')
        assert p.poll() is None
    base='devid=synthetic-device eventtime=1791972000123456789 logid=0100032001 type=event subtype=system'
    def wire(level):
        row=(base+' level='+level+' msg="synthetic site event"').encode()
        return str(len(row)).encode()+b' '+row
    def originals(directory,count):
        records=[]
        for path in sorted(directory.glob('record-*')):
            assert not path.is_symlink();raw=path.read_bytes();assert len(raw)<131072
            length,crc,hcrc=struct.unpack('<III',raw[:12]);assert len(raw)==length+12
            assert zlib.crc32(raw[:8])==hcrc and zlib.crc32(raw[12:])==crc
            records.append(json.loads(raw[12:])['event'])
        assert len(records)==count;return records
    try:
        ca=fixture.ca('syslog-ca');bad_ca=fixture.ca('untrusted-ca')
        receiver=fixture.leaf(ca,'receiver','serverAuth')
        peer=fixture.leaf(ca,'allowed','clientAuth')
        wrong=fixture.leaf(ca,'wrong-scope','clientAuth')
        expired=fixture.leaf(ca,'expired','clientAuth',expired=True)
        untrusted=fixture.leaf(bad_ca,'untrusted','clientAuth')
        tls_path=fixture.material('receiver',receiver,[ca])
        digest=hashlib.sha256(ssl.PEM_cert_to_DER_cert(peer.with_suffix('.pem').read_text())).hexdigest()
        listen,mp,server_port=port(),port(),port()
        spool=output/'tls-spool'
        common=[str(agent),'--server',f'http://127.0.0.1:{server_port}','--spool-dir',str(spool),
                '--syslog-listen',f'127.0.0.1:{listen}','--format','fortigate','--source-name','site-tls',
                '--source-type','syslog','--metrics-listen',f'127.0.0.1:{mp}',
                '--syslog-tls-config',str(tls_path),'--syslog-peer-sha256',digest,
                '--max-spool-events','2','--flush-ms','20','--retry-base-ms','20','--retry-max-ms','100','--shutdown-timeout-ms','1000']
        env=dict(environment,SIGNAL_AGENT_API_TOKEN=token)
        p=start('tls-offline',common,env);ready(p,mp)
        def connect(leaf=peer):
            wait(lambda:metrics(mp).get('signal_agent_syslog_connections')==0, 'prior connection not retired')
            context=fixture.context(ca,leaf)
            return context.wrap_socket(socket.create_connection(('127.0.0.1',listen),timeout=2),server_hostname='localhost')
        for leaf in [None,wrong,expired,untrusted]:
            before=metrics(mp).get('signal_agent_syslog_refusals_total',0)
            try:
                with connect(leaf) as s:s.sendall(wire('notice'));s.settimeout(2);assert s.recv(1)==b''
            except (ssl.SSLError,ConnectionResetError,BrokenPipeError):pass
            wait(lambda:metrics(mp).get('signal_agent_syslog_refusals_total',0)>before,'TLS refusal not counted')
            assert metrics(mp)['signal_agent_spool_events']==0
        checks.append('missing_expired_untrusted_and_wrong_pinned_peer_refused_without_spooling')
        with connect() as s:
            wait(lambda:metrics(mp).get('signal_agent_syslog_connections')==1,'active connection missing')
            extra=socket.create_connection(('127.0.0.1',listen),timeout=2);extra.settimeout(2)
            try:assert extra.recv(1)==b''
            except ConnectionResetError:pass
            finally:extra.close()
            checks.append('connection_capacity_one_refuses_extra_peer')
            payload=wire('notice')+wire('error')+wire('warning');s.sendall(payload[:1]);s.sendall(payload[1:7]);s.sendall(payload[7:])
            wait(lambda:metrics(mp).get('signal_agent_spool_events')==2,'offline complete frames not synced')
            wait(lambda:metrics(mp).get('signal_agent_syslog_pending_frames')==1,'saturated spool did not hold bounded pending frame')
            assert metrics(mp)['signal_agent_syslog_frame_capacity']==1
            assert metrics(mp)['signal_agent_spool_capacity_events']==2
            assert metrics(mp)['signal_agent_syslog_buffered_bytes']<=metrics(mp)['signal_agent_syslog_buffer_capacity_bytes']
            checks.append('saturated_spool_holds_one_bounded_unacknowledged_frame')
            original=originals(spool,2)
            assert metrics(mp)['signal_agent_spool_capacity_events']>=2
            kill(p)
        checks.append('split_and_coalesced_frames_synced_before_physical_crash')
        server_env=dict(environment,SIGNAL_LISTEN=f'127.0.0.1:{server_port}',SIGNAL_API_TOKEN=token,
            SIGNAL_WAL_DIR=str(output/'wal'),SIGNAL_STORAGE_DIR=str(output/'events'),
            SIGNAL_FINDINGS_DIR=str(output/'findings'),SIGNAL_STORAGE_FLUSH_MS='10')
        srv=start('server',[str(server)],server_env)
        def server_ready():
            try:return srv.poll() is None and request(server_port,'/readyz') is not None
            except (OSError,http.client.HTTPException):return False
        wait(server_ready,'server startup')
        p=start('tls-restarted',common,env);ready(p,mp)
        wait(lambda:metrics(mp).get('signal_agent_spool_events')==0,'offline spool not drained')
        wait(lambda:len(rows(server_port,'site-tls'))==2,'replayed records absent')
        actual=rows(server_port,'site-tls')
        assert {e['id']:e for e in actual}=={e['id']:e for e in original}
        checks.append('WAN_outage_SIGKILL_restart_exact_original_ids_and_canonical_bytes')
        for bad in [b'65537 ',b'2 x',b'1 x']:
            before=metrics(mp).get('signal_agent_syslog_refusals_total',0)
            with connect() as s:s.sendall(bad)
            wait(lambda:metrics(mp).get('signal_agent_syslog_refusals_total',0)>before,'malformed/refused EOF not counted')
        checks.append('oversized_frame_incomplete_EOF_and_invalid_record_counted')
        assert len(rows(server_port,'site-tls'))==2
        idle=connect();wait(lambda:metrics(mp).get('signal_agent_syslog_connections')==1,'idle peer not active');began=time.monotonic()
        idle.sendall(b'1');time.sleep(20);idle.sendall(b'2')
        wait(lambda:metrics(mp).get('signal_agent_syslog_connections')==0,'idle deadline did not retire peer',seconds=13)
        assert time.monotonic()-began<33;idle.close();checks.append('partial_frame_trickling_does_not_reset_original_30_second_deadline')
        active=connect();active.sendall(b'1');wait(lambda:metrics(mp).get('signal_agent_syslog_buffered_bytes',0)>0,'active partial frame missing')
        began=time.monotonic();p.terminate();assert p.wait(timeout=5)==0
        assert time.monotonic()-began<2;active.settimeout(1)
        try:assert active.recv(1)==b''
        except (ssl.SSLError,ConnectionResetError):pass
        finally:active.close()
        checks.append('shutdown_cancels_active_TLS_partial_frame_and_releases_listener')
        checks.append('shutdown_retires_listener_and_drained_spool')
        # Explicit plaintext loopback fixture, independent source and spool.
        plain_port,plain_metrics=port(),port()
        plain=[str(agent),'--server',f'http://127.0.0.1:{server_port}','--spool-dir',str(output/'plain-spool'),
            '--syslog-listen',f'127.0.0.1:{plain_port}','--format','fortigate','--source-name','site-plain',
            '--metrics-listen',f'127.0.0.1:{plain_metrics}','--flush-ms','20']
        q=start('plain',plain,env);ready(q,plain_metrics)
        with socket.create_connection(('127.0.0.1',plain_port),timeout=2) as s:s.sendall(wire('warning'))
        wait(lambda:len(rows(server_port,'site-plain'))==1,'plain loopback record absent')
        assert rows(server_port,'site-plain')[0]['severity']=='warn'
        q.terminate();assert q.wait(timeout=5)==0
        checks.append('explicit_loopback_TCP_severity_and_local_spool_delivery')
        denied=subprocess.run([str(agent),'--syslog-listen','0.0.0.0:6514','--format','fortigate','--source-name','remote'],env=env,capture_output=True,timeout=5)
        assert denied.returncode!=0;checks.append('remote_plaintext_configuration_refused')
        srv.terminate();assert srv.wait(timeout=5)==0
        for log in logs:
            raw=log.read_bytes();assert len(raw)<=1048576 and token.encode() not in raw and b'BEGIN PRIVATE KEY' not in raw
        report={'status':'passed_simulated','checks':checks,'original_ids':sorted(e['id'] for e in original),
            'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'apps/signal-agent/src/syslog.rs',ROOT/'apps/signal-agent/src/runtime.rs',ROOT/'apps/signal-agent/src/config.rs',ROOT/'crates/signal-collector-sdk/src/transport/tls.rs']},
            'binaries':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [agent,server]},
            'scope':'Owned local TCP/mTLS receiver with synthetic device/certificates, local durable spool/outage/SIGKILL replay; actual firmware/device buffers/site loss/coverage not qualified'}
        (output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'checks':len(checks),'report':str(output/'report.json')}))
    finally:
        for p in reversed(processes):
            if p.poll() is None:p.kill();p.wait(timeout=5)
        fixture.cleanup()
        assert all(p.poll() is not None for p in processes) and not fixture.private.exists()
        report_path=output/'report.json'
        if report_path.exists():
            report=json.loads(report_path.read_text());report['owned_cleanup']=True
            report_path.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('agent',type=Path);parser.add_argument('server',type=Path);parser.add_argument('output',type=Path);args=parser.parse_args()
    run(args.agent.resolve(),args.server.resolve(),args.output.resolve())

#!/usr/bin/env python3
"""Validate the synthetic vendor corpus, not a production normalization adapter."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import tomllib
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {'aws.cloudtrail', 'aws.cloudwatch', 'aws.rds', 'aws.alb', 'aws.nlb',
           'aws.eks', 'aws.ecs', 'cloudflare', 'office365', 'cato.vpn', 'fortigate'}
SEVERITIES = {'trace', 'debug', 'info', 'warn', 'error', 'critical'}
RISKS = {'none', 'low', 'medium', 'high', 'critical'}
ACCOUNT = '000000000001'
CAP = 2 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(root, name, expected_hash=None):
    require(re.fullmatch(r'[a-z0-9-]+\.(json|ndjson)', name) is not None, 'unsafe sample filename')
    path = root / name
    require(not path.is_symlink() and path.is_file(), 'sample must be a regular file')
    with path.open('rb') as stream:
        data = stream.read(CAP + 1)
    require(len(data) <= CAP, 'sample exceeds byte cap')
    if expected_hash:
        require(digest(data) == expected_hash, 'sample file hash mismatch')
    return data


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None, 'timestamp needs timezone')
    return result


def check_case(case, source):
    event = case['expected']; raw = case['raw']; fmt = case['raw_format']
    require(isinstance(raw, str) and len(raw.encode()) <= 65536, 'raw byte limit')
    require(digest(raw.encode()) == case['raw_sha256'], 'raw hash mismatch')
    require(event['attributes']['log']['original'] == raw, 'original bytes changed')
    require(event['attributes']['sample'] == {'synthetic': True, 'case_id': case['case_id']}, 'synthetic marker')
    require(event['schema_version'] == 1 and uuid.UUID(event['id']).int != 0, 'event version/id')
    require(event['source']['type'] == source and case['case_id'].startswith(source + '.'), 'source identity')
    require(event['severity'] in SEVERITIES and case['security']['severity'] in RISKS, 'severity domains')
    require(case['security']['confidence'] == 'illustrative', 'sample must not claim detection confidence')
    require(isinstance(case['security']['required_context'], list), 'context requirements')
    at = timestamp(event['timestamp'])
    require(timestamp(event['observed_at']) >= at, 'observed time precedes event')
    if source.startswith('aws.'):
        require(event['resource']['account_id'] == ACCOUNT, 'non-synthetic AWS account')
        require(all(a == ACCOUNT for a in re.findall(r'arn:aws:[^:]*:[^:]*:(\d{12}):', raw)), 'non-synthetic ARN account')
    require(re.search(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|-----BEGIN .*PRIVATE KEY', raw) is None, 'credential-like material')
    action = None; outcome = None; raw_at = None; severity = None
    if fmt in {'json', 'cloudtrail-json'}:
        data = json.loads(raw)
        require(data['eventVersion'] == '1.11' and data['recipientAccountId'] == ACCOUNT, 'CloudTrail envelope')
        action = data['eventSource'].split('.')[0] + ':' + data['eventName']
        outcome = 'failure' if data.get('errorCode') else 'success'; raw_at = data['eventTime']; severity = 'info'
    elif fmt == 'cloudwatch-decoded-json':
        data = json.loads(raw)
        require(data['messageType'] == 'DATA_MESSAGE' and data['owner'] == ACCOUNT, 'decoded CloudWatch envelope')
        require(len(data['logEvents']) == 1, 'one reference event per subscription fixture')
        log = data['logEvents'][0]; payload = json.loads(log['message'])
        require(datetime.fromtimestamp(log['timestamp'] / 1000, timezone.utc) == at, 'CloudWatch millisecond time')
        action = payload['action']; outcome = payload['outcome']; raw_at = payload['timestamp']
        severity = {'DEBUG': 'debug', 'INFO': 'info', 'WARN': 'warn', 'ERROR': 'error', 'CRITICAL': 'critical'}[payload['level']]
    elif fmt == 'postgresql-text':
        match = re.fullmatch(r'(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC \[\d+\]: user=[^,]+,db=[^,]+,app=[^,]+,client=[^ ]+ (DEBUG1|LOG|FATAL|PANIC):  .+\n', raw)
        require(match is not None, 'configured PostgreSQL text prefix')
        raw_at = match[1].replace(' ', 'T') + 'Z'
        severity = {'DEBUG1': 'debug', 'LOG': 'info', 'FATAL': 'error', 'PANIC': 'critical'}[match[2]]
    elif fmt == 'alb-access-v1':
        fields = shlex.split(raw)
        require(len(fields) == 33 and fields[0] == 'https', 'ALB field layout')
        require(fields[12].startswith('GET https://') and fields[12].endswith(' HTTP/1.1'), 'ALB quoted request')
        code = int(fields[8]); raw_at = fields[1]
        outcome = 'failure' if code >= 400 else 'success'
        severity = 'error' if code >= 500 else 'warn' if code >= 400 else 'info'
    elif fmt == 'nlb-tls-2.0':
        fields = shlex.split(raw)
        require(len(fields) == 22 and fields[:2] == ['tls', '2.0'], 'NLB TLS-only field layout')
        require(fields[15] in {'-', 'tlsv10', 'tlsv11', 'tlsv12', 'tlsv13'}, 'NLB TLS version')
        require(fields[13] == '-' and 'HTTP/' not in raw, 'NLB has no HTTP request or certificate serial')
        require(timestamp(fields[21]) <= timestamp(fields[2]), 'NLB connection creation time')
        raw_at = fields[2]; outcome = 'failure' if fields[15] == '-' else 'success'
    elif fmt == 'kubernetes-audit-v1':
        data = json.loads(raw)
        require(data['apiVersion'] == 'audit.k8s.io/v1' and data['kind'] == 'Event' and data['stage'] == 'ResponseComplete', 'Kubernetes audit envelope')
        require(data['level'] != 'Metadata' or 'requestObject' not in data, 'Metadata audit must not invent requestObject')
        if case['security']['severity'] in {'high', 'critical'}:
            require(data['level'] == 'Request' and 'requestObject' in data, 'pod/RBAC detection needs request-level evidence')
        ref = data['objectRef']; action = 'kubernetes.' + data['verb'] + '.' + ref['resource']
        if ref.get('subresource'): action += '.' + ref['subresource']
        outcome = 'failure' if data['responseStatus']['code'] >= 400 else 'success'
        raw_at = data['requestReceivedTimestamp']; severity = 'warn' if outcome == 'failure' else 'info'
    elif fmt == 'ecs-eventbridge-json':
        data = json.loads(raw)
        require(data['source'] == 'aws.ecs' and data['detail-type'] == 'ECS Task State Change' and data['account'] == ACCOUNT, 'ECS EventBridge envelope')
        require(case['security']['severity'] == 'none', 'task lifecycle alone is not a security detection')
        action = 'ecs.task.state'; outcome = 'failure' if data['detail']['lastStatus'] == 'STOPPED' else 'success'
        raw_at = data['time']; severity = 'error' if outcome == 'failure' else 'info'
    elif fmt == 'ecs-application-json':
        data = json.loads(raw); raw_at = data['timestamp']; action = data['action']; outcome = data['outcome']
        severity = {'WARN': 'warn', 'CRITICAL': 'critical'}[data['level']]
    elif fmt == 'cloudflare-firewall-json':
        data = json.loads(raw)
        require(data['Kind'] == 'firewall' and isinstance(data['Datetime'], str), 'Cloudflare dataset/time option')
        require(data['Action'] in {'allow', 'block', 'managedchallenge', 'log'}, 'Cloudflare selected action enum')
        require(data['Source'] in {'firewallcustom', 'firewallmanaged', 'ratelimit'}, 'Cloudflare selected product enum')
        action = 'cloudflare.' + data['Action']; outcome = 'success' if data['Action'] in {'allow', 'log'} else 'blocked'
        raw_at = data['Datetime']; severity = 'info' if data['Action'] == 'allow' else 'warn'
    elif fmt == 'office365-audit-json':
        data = json.loads(raw)
        require(data['RecordType'] in {1, 15} and data['Workload'] in {'Exchange', 'AzureActiveDirectory'}, 'Microsoft 365 workload/record type')
        action = 'office365.' + data['Operation']; raw_at = data['CreationTime'] + 'Z'
        # STS transport ResultStatus can succeed even when authentication fails.
        failed = data['RecordType'] == 15 and (data['Operation'] == 'UserLoginFailed' or data.get('ErrorCode', '0') != '0' or bool(data.get('LogonError')))
        outcome = 'failure' if failed else 'success'; severity = 'warn' if failed else 'info'
    elif fmt == 'cato-eventrecord-json':
        data = json.loads(raw)
        require(isinstance(data['fieldsMap'], dict) and all(isinstance(v, str) for v in data['fieldsMap'].values()), 'Cato EventRecord projection')
        require(data['fieldsMap']['event_type'] in {'Connectivity', 'Security'}, 'Cato event type')
        require(case['security']['required_context'], 'Cato enum confirmation required')
        raw_at = data['time']
    elif fmt == 'fortios-key-value':
        fields = dict(token.split('=', 1) for token in shlex.split(raw))
        require(re.fullmatch(r'\d{10}', fields['logid']) is not None, 'FortiOS full log ID')
        require(fields['tz'] == '+0000', 'fixture timezone')
        raw_at = fields['date'] + 'T' + fields['time'] + 'Z'
        require(int(fields['eventtime']) == int(at.timestamp()) * 1000000000, 'FortiOS nanosecond time')
        action = 'fortigate.' + fields['action']; outcome = 'failure' if fields['action'] == 'ssl-login-fail' else 'success'
        severity = {'information': 'info', 'notice': 'info', 'alert': 'critical'}[fields['level']]
    else:
        raise ValueError('unknown selected vendor format')
    require(timestamp(raw_at) == at, 'native timestamp changed')
    if action is not None: require(event['attributes']['event']['action'] == action, 'native action changed')
    if outcome is not None: require(event['attributes']['event']['outcome'] == outcome, 'native outcome changed')
    if severity is not None: require(event['severity'] == severity, 'log severity mapping changed')


def validate(root):
    manifest = json.loads(read(root, 'manifest.json'))
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    require(manifest['schema_version'] == 1 and manifest['synthetic'] is True and manifest['corpus_version'] == version, 'corpus version/synthetic status')
    require(manifest['normalization_status'] == 'reference-examples-only', 'normalization claim')
    require({s['source'] for s in manifest['sources']} == SOURCES and len(manifest['sources']) == 11, 'required source coverage')
    cases = []; ids = set(); event_ids = set()
    for source in manifest['sources']:
        bundle = json.loads(read(root, source['file'], source['sha256']))
        require(bundle['source'] == source['source'] and len(bundle['cases']) == source['case_count'] == 5, 'source case count')
        require(any(c['security']['severity'] == 'none' for c in bundle['cases']) and any(c['security']['severity'] != 'none' for c in bundle['cases']), 'benign and security examples per source')
        for case in bundle['cases']:
            require(case['case_id'] not in ids and case['expected']['id'] not in event_ids, 'duplicate case/event identity')
            ids.add(case['case_id']); event_ids.add(case['expected']['id']); check_case(case, source['source']); cases.append(case)
    expected = [c['expected'] for c in cases]
    ndjson = [json.loads(line) for line in read(root, manifest['canonical'], manifest['canonical.ndjson_sha256']).splitlines()]
    batch = json.loads(read(root, manifest['ingest_batch'], manifest['ingest-batch.json_sha256']))
    require(ndjson == expected and batch == {'events': expected}, 'canonical aggregates differ from case expectations')
    require({c['security']['severity'] for c in cases} == RISKS, 'all security severity examples required')
    return cases


def self_test(cases):
    tests = [
        ('office365.login-failure', lambda c: c['expected']['attributes']['event'].update(outcome='success')),
        ('fortigate.vpn-bad-password', lambda c: c['expected'].update(severity='warn')),
        ('aws.cloudtrail.stop-audit', lambda c: c['expected']['resource'].update(account_id='123456789012')),
        ('aws.eks.privileged-pod', lambda c: change_raw(c, lambda d: d.pop('requestObject'))),
        ('aws.nlb.tls-success', lambda c: append_raw(c, 'GET / HTTP/1.1\n')),
        ('aws.cloudwatch.login-failure', lambda c: change_raw(c, lambda d: d.update(messageType='CONTROL_MESSAGE'))),
        ('aws.alb.health', lambda c: c['expected']['attributes']['log'].update(original='changed')),
    ]
    for case_id, mutate in tests:
        case = copy.deepcopy(next(c for c in cases if c['case_id'] == case_id)); mutate(case)
        try: check_case(case, case['expected']['source']['type'])
        except (ValueError, KeyError): continue
        raise ValueError('negative guard accepted: ' + case_id)
    return len(tests)


def append_raw(case, suffix):
    raw = case['raw'] + suffix
    case.update(raw=raw, raw_sha256=digest(raw.encode()))
    case['expected']['attributes']['log']['original'] = raw


def change_raw(case, mutate):
    data = json.loads(case['raw']); mutate(data); raw = json.dumps(data) + '\n'
    case.update(raw=raw, raw_sha256=digest(raw.encode()))
    case['expected']['attributes']['log']['original'] = raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true'); args = parser.parse_args()
    cases = validate(ROOT / 'examples/logs')
    guards = self_test(cases) if args.self_test else 0
    print(json.dumps({'status': 'passed', 'sources': len(SOURCES), 'cases': len(cases), 'negative_guards': guards,
                      'scope': 'synthetic fixture/native-envelope validation; no collector qualification'}))


if __name__ == '__main__':
    main()

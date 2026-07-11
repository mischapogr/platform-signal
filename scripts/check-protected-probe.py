#!/usr/bin/env python3
"""Exercise the current native probe/exec adapter in an existing local runtime image.

The image is only a runtime substrate, not a qualified current release image.
No build, pull, push or publication. Synthetic keys are deleted after owned cleanup.
"""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('transport_fixture', ROOT / 'tests/integration/transport-server-process.py')
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--server', type=Path, default=ROOT / 'target/debug/signal-server')
    parser.add_argument('--agent', type=Path, default=ROOT / 'target/debug/signal-agent')
    parser.add_argument('--adapter', type=Path, default=ROOT / 'target/signal-healthcheck')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}', args.image):
        parser.error('bounded existing image reference required')
    run = FIXTURE.Run(args.server.resolve(), args.agent.resolve(), args.output.resolve())
    owner_id = uuid.uuid4().hex
    containers = []
    command_index = 0
    def docker(*arguments):
        nonlocal command_index
        command_index += 1
        if command_index > 24:
            raise RuntimeError('owned Docker command capacity')
        log_path = run.output / ('docker-' + str(command_index) + '.log')
        with log_path.open('xb') as log:
            FIXTURE.HELP.NATIVE.run_bounded(['docker', *arguments], log, timeout=10, grace=0.1)
        with log_path.open('rb') as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise RuntimeError('owned Docker reply capacity')
        return raw.decode('utf8').strip()
    failure = None
    image_id = None
    began = datetime.datetime.now(datetime.timezone.utc).isoformat()
    def interrupted(_kind, _frame):
        raise KeyboardInterrupt()
    previous = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGINT)}
    try:
        image_id = docker('image', 'inspect', '--format', '{{.Id}}', args.image)
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
            raise RuntimeError('image identity invalid')
        ca, foreign = run.ca('probe-original'), run.ca('probe-foreign')
        server, client = run.leaf(ca, 'probe-server', 'serverAuth'), run.leaf(ca, 'probe-client', 'clientAuth')
        server_config = run.material('probe-server', server, [ca])
        client_config = run.material('probe-client', client, [ca])
        wrong_config = run.material('probe-wrong-root', client, [foreign])
        run.start_server(server_config, run.context(ca, client), 'server')
        # Host scratch stays 0700. Only selected synthetic files are bind-mounted
        # read-only; 0444 permits image UID65532 without exposing the parent tree.
        for path in (client_config, wrong_config):
            path.chmod(0o444)
        owner = run.owner('adapter')
        for label, config, expected in [('valid', client_config, 0), ('wrong-root', wrong_config, 1), ('missing', None, 1)]:
            name = 'signal-probe-' + owner_id + '-' + label
            containers.append(name)
            command = ['docker', 'run', '--name', name, '--label', 'signal.probe.owner=' + owner_id,
                '--network', 'host', '--user', '65532:65532', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--pids-limit', '64', '--memory', '256m', '--cpus', '1', '--no-healthcheck',
                '--entrypoint', '/usr/local/bin/signal-healthcheck',
                '--mount', 'type=bind,source=' + str(args.agent.resolve()) + ',target=/usr/local/bin/signal-agent,readonly',
                '--mount', 'type=bind,source=' + str(args.adapter.resolve()) + ',target=/usr/local/bin/signal-healthcheck,readonly',
                '--env', 'SIGNAL_TLS_CONFIG=/etc/signal/server.json',
                '--env', 'SIGNAL_HEALTHCHECK_ADDR=127.0.0.1:' + str(run.port)]
            if config is not None:
                command += ['--mount', 'type=bind,source=' + str(config) + ',target=/probe.json,readonly',
                            '--env', 'SIGNAL_PROBE_TLS_CONFIG=/probe.json']
            command.append(image_id)
            started = time.monotonic()
            process = owner.spawn(command, run.environment, label)
            run.wait(lambda: owner.exited(process) is not None, 'container probe deadline', 5)
            assert owner.stop(process) == expected, 'container probe exit mismatch'
            assert time.monotonic() - started < 4, 'container probe supervisor budget'
            assert docker('inspect', '--format', '{{.Config.User}}', name) == '65532:65532', 'probe container user mismatch'
            state = json.loads(docker('inspect', '--format', '{{json .State}}', name))
            assert state['Status'] == 'exited' and state['ExitCode'] == expected, 'container runtime failure is not probe denial'
            assert owner.logs[-1].stat().st_size == 0, 'probe emitted Docker diagnostics'
            assert FIXTURE.absolute_request(run.trusted_context, run.port, '/readyz', run.token)[0] == 200
            run.mark('actual_nonroot_container_adapter_' + label)
    except BaseException as exc:
        failure = type(exc).__name__
    finally:
        for kind in previous:
            signal.signal(kind, signal.SIG_IGN)
        # Retire/reap all launch processes before inspecting/removing their containers.
        # An uncertain daemon/container cleanup keeps synthetic scratch for recovery.
        run.retire_processes()
        for name in containers:
            try:
                selected = docker('inspect', '--format', '{{index .Config.Labels "signal.probe.owner"}}', name)
                if selected != owner_id:
                    raise RuntimeError('container ownership mismatch')
                docker('rm', '--force', name)
            except BaseException as exc:
                run.cleanup_errors.append('owned container cleanup: ' + type(exc).__name__)
        run.cleanup()
        for kind, handler in previous.items():
            signal.signal(kind, handler)
        report = {'schema_version': 1, 'status': 'passed_simulated' if failure is None and not run.cleanup_errors else 'failed',
            'started_at': began, 'completed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'checks': run.checks, 'failure_type': failure, 'cleanup_errors': run.cleanup_errors,
            'image_id': image_id, 'server_sha256': FIXTURE.HELP.NATIVE.sha256(run.server_binary),
            'agent_sha256': FIXTURE.HELP.NATIVE.sha256(run.agent_binary),
            'adapter_sha256': FIXTURE.HELP.NATIVE.sha256(args.adapter),
            'qualification': 'Current debug binaries and current exec adapter mounted into existing runtime image. Not current release/image, Kubernetes, ARM64 or cloud qualification.'}
        (run.output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Protected container probe gate: ' + report['status'])
    return 0 if report['status'] == 'passed_simulated' else 1


if __name__ == '__main__':
    raise SystemExit(main())

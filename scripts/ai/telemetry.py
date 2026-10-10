#!/usr/bin/env python3
"""Local session counters and MCP timings; never retain prompts or tool payloads."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from uuid import uuid4

import usage

ROOT = Path(__file__).resolve().parents[2]


def claude_counts():
    directory = Path.home() / '.claude/projects' / str(ROOT).replace('/', '-')
    messages = {}
    for path in directory.rglob('*.jsonl'):
        try:
            with path.open() as stream:
                for line in stream:
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    message = event.get('message', {})
                    counts = message.get('usage')
                    if event.get('type') != 'assistant' or not counts or not message.get('id'):
                        continue
                    key = (event.get('sessionId'), message['id'])
                    previous = messages.get(key, {})
                    messages[key] = {name: max(previous.get(name, 0), counts.get(name, 0))
                                     for name in ('input_tokens', 'output_tokens',
                                                  'cache_creation_input_tokens', 'cache_read_input_tokens')}
        except OSError:
            continue
    total = Counter()
    for counts in messages.values():
        total.update(counts)
    return {'messages': len(messages), 'tokens': dict(total)}


def capture(path):
    try:
        result = usage.snapshot(Path.home() / '.codex')
        result['claude'] = claude_counts()
        path.write_text(json.dumps(result, indent=2) + '\n')
        return result
    except (OSError, ValueError, usage.sqlite3.Error) as error:
        path.write_text(json.dumps({'unavailable': type(error).__name__}) + '\n')
        return None


def run(client, argv, mcp=False):
    directory = ROOT / 'target/ai-telemetry' / (
        datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid4().hex[:12])
    directory.mkdir(parents=True)
    started = time.monotonic()
    before = None if mcp else capture(directory / 'before.json')
    pending = {}
    lock = threading.Lock()
    metrics = (directory / 'mcp.jsonl').open('w') if mcp else None
    process = None
    previous_handlers = {}

    def forward(number, _frame):
        if process is not None and process.poll() is None:
            process.send_signal(number)

    def copy_input():
        try:
            while raw := sys.stdin.buffer.readline(4 * 1024 * 1024 + 1):
                if len(raw) <= 4 * 1024 * 1024:
                    try:
                        request = json.loads(raw)
                        if 'id' in request:
                            method = request.get('method', '')
                            tool = request.get('params', {}).get('name') if method == 'tools/call' else None
                            with lock:
                                if len(pending) < 1024:
                                    pending[request['id']] = (time.monotonic(), method, tool, len(raw))
                    except (ValueError, TypeError, AttributeError):
                        pass
                process.stdin.write(raw)
                process.stdin.flush()
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    exit_code = 1
    try:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous_handlers[number] = signal.signal(number, forward)
        process = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.PIPE if mcp else None,
                                   stdout=subprocess.PIPE if mcp else None)
        if mcp:
            threading.Thread(target=copy_input, daemon=True).start()
            while raw := process.stdout.readline(4 * 1024 * 1024 + 1):
                sys.stdout.buffer.write(raw)
                sys.stdout.buffer.flush()
                if len(raw) > 4 * 1024 * 1024:
                    continue
                try:
                    response = json.loads(raw)
                    with lock:
                        request = pending.pop(response.get('id'), None)
                    if request:
                        then, method, tool, input_bytes = request
                        metrics.write(json.dumps({'method': method, 'tool': tool,
                            'elapsed_ms': round((time.monotonic() - then) * 1000, 3),
                            'input_bytes': input_bytes, 'output_bytes': len(raw),
                            'error': 'error' in response or bool(response.get('result', {}).get('isError'))}) + '\n')
                        metrics.flush()
                except (ValueError, TypeError, AttributeError):
                    pass
        exit_code = process.wait()
    except OSError as error:
        print(f'{client} launch failed: {type(error).__name__}', file=sys.stderr)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
        if metrics:
            metrics.close()
        after = None if mcp else capture(directory / 'after.json')
        summary = {'schema_version': 1, 'client': client, 'mcp': mcp,
                   'elapsed_seconds': round(time.monotonic() - started, 3),
                   'exit_code': exit_code, 'scope': 'Local project telemetry; concurrent work included; not billing.'}
        if before and after:
            try:
                summary['codex_delta'] = usage.compare(after, before)
            except ValueError as error:
                summary['codex_delta_unavailable'] = str(error)
            b, a = before['claude']['tokens'], after['claude']['tokens']
            delta = {key: a.get(key, 0) - b.get(key, 0) for key in set(b) | set(a)}
            if all(value >= 0 for value in delta.values()):
                summary['claude_delta'] = delta
            else:
                summary['claude_delta_unavailable'] = 'Counters decreased'
        (directory / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        if not mcp:
            print(f'Local telemetry: {directory / "summary.json"}', file=sys.stderr)
    return exit_code if exit_code >= 0 else 128 - exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mcp', action='store_true')
    parser.add_argument('client', choices=['codex', 'claude', 'serena', 'codegraph'])
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not argv:
        parser.error('a command is required')
    return run(args.client, argv, args.mcp)


if __name__ == '__main__':
    raise SystemExit(main())

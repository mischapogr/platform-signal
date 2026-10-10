#!/usr/bin/env python3
"""Prove discovery and live read queries; run with the Serena virtualenv Python."""
import argparse
import asyncio
from contextlib import AsyncExitStack
from datetime import timedelta
import json
from pathlib import Path
import time
import tomllib

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

ROOT = Path(__file__).resolve().parents[2]


async def check(name, live):
    settings = tomllib.loads((ROOT / '.codex/config.toml').read_text())['mcp_servers'][name]
    started = time.monotonic()
    async with AsyncExitStack() as stack:
        if 'url' in settings:
            read, write, _ = await stack.enter_async_context(streamablehttp_client(settings['url']))
        else:
            read, write = await stack.enter_async_context(stdio_client(StdioServerParameters(
                command=settings['command'], args=settings['args'], cwd=str(ROOT))))
        session = await stack.enter_async_context(ClientSession(read, write,
            read_timeout_seconds=timedelta(seconds=120)))
        info = await session.initialize()
        listed = await session.list_tools()
        names = {tool.name for tool in listed.tools}
        expected = {'serena': {'get_symbols_overview', 'find_symbol', 'find_referencing_symbols'},
                    'codegraph': {'codegraph_search', 'codegraph_status'},
                    'openaiDeveloperDocs': {'search_openai_docs', 'fetch_openai_doc'}}[name]
        if not expected <= names:
            raise RuntimeError(f'{name}: missing expected tools {sorted(expected - names)}')
        result = {'server': name, 'server_info': info.serverInfo.model_dump(),
                  'tools': sorted(names), 'discovery': 'passed', 'live': 'not_checked'}
        if live:
            tool, arguments, marker = {
                'serena': ('get_symbols_overview',
                           {'relative_path': 'crates/signal-storage/src/lib.rs', 'max_answer_chars': 12000}, 'EventStore'),
                'codegraph': ('codegraph_search', {'query': 'EventStore', 'limit': 5}, 'EventStore'),
                'openaiDeveloperDocs': ('search_openai_docs', {'query': 'Codex MCP configuration', 'limit': 2}, 'codex'),
            }[name]
            response = await session.call_tool(tool, arguments)
            content = '\n'.join(getattr(item, 'text', '') for item in response.content)
            if response.isError or marker.lower() not in content.lower():
                raise RuntimeError(f'{name}: live query failed expected marker {marker}')
            result['live'] = 'passed'
            result['response_characters'] = len(content)
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', choices=['serena', 'codegraph', 'openaiDeveloperDocs'], required=True)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = asyncio.run(asyncio.wait_for(check(args.server, args.live), timeout=180))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

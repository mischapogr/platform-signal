#!/usr/bin/env python3
"""Initialize the actual project MCP; optionally prove a live documentation lookup."""

import argparse
import json
from pathlib import Path
import selectors
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Resolve Tokio via the Context7 service")
    args = parser.parse_args()
    process = subprocess.Popen(
        ["bash", "scripts/ai/context7"], cwd=ROOT,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    pending = bytearray()

    def send(payload):
        process.stdin.write((json.dumps(payload) + "\n").encode())
        process.stdin.flush()

    def request(identifier, method, params):
        send({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params})
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            while b"\n" in pending:
                raw, _, remainder = pending.partition(b"\n")
                pending[:] = remainder
                response = json.loads(raw)
                if response.get("id") == identifier:
                    if "error" in response:
                        raise RuntimeError(f"MCP {method} failed: {response['error'].get('code')}")
                    if response.get("result", {}).get("isError"):
                        raise RuntimeError(f"MCP {method} returned a tool error")
                    return response["result"]
            ready = selector.select(max(0, deadline - time.monotonic()))
            if ready:
                chunk = process.stdout.read(65536)
                if not chunk:
                    raise RuntimeError(f"MCP exited during {method}")
                pending.extend(chunk)
                if len(pending) > 2 * 1024 * 1024:
                    raise RuntimeError("MCP response exceeded the 2 MiB verification limit")
        raise TimeoutError(f"MCP {method} exceeded 60 seconds")

    try:
        initialized = request(1, "initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "platform-signal-mcp-check", "version": "0.1.0"},
        })
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = request(2, "tools/list", {})["tools"]
        names = {tool["name"] for tool in tools}
        required = {"resolve-library-id", "query-docs"}
        if not required <= names:
            raise RuntimeError("Context7 documentation tools are missing")
        info = initialized["serverInfo"]
        print(f"MCP initialized: {info['name']} {info['version']}; tools={','.join(sorted(names))}")
        if args.live:
            result = request(3, "tools/call", {
                "name": "resolve-library-id",
                "arguments": {"libraryName": "tokio", "query": "Rust Tokio bounded mpsc channel documentation"},
            })
            content = "\n".join(c.get("text", "") for c in result.get("content", []))
            if "/tokio-rs/tokio" not in content:
                raise RuntimeError("Live lookup did not resolve the expected Tokio library")
            print("Live Context7 lookup verified: /tokio-rs/tokio")
    finally:
        selector.close()
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        for stream in (process.stdin, process.stdout):
            stream.close()


if __name__ == "__main__":
    main()

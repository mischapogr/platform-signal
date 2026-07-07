#!/usr/bin/env python3
"""Check crate ownership using Cargo metadata, including uncommitted files."""

import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {
    "signal-event": set(),
    "signal-protocol": {"signal-event"},
    "signal-ingest": {"signal-event", "signal-protocol"},
    "signal-buffer": {"signal-event", "signal-protocol"},
    "signal-storage": {"signal-event", "signal-protocol"},
    "signal-query": {"signal-event", "signal-protocol", "signal-storage"},
    "signal-rules": {"signal-event", "signal-findings"},
    "signal-findings": {"signal-event"},
    "signal-collector-sdk": {"signal-event", "signal-protocol"},
    "signal-coverage": {"signal-collector-sdk"},
    "signal-server": {
        "signal-event", "signal-protocol", "signal-ingest", "signal-buffer",
        "signal-storage", "signal-query", "signal-rules", "signal-findings",
        "signal-collector-sdk", "signal-coverage",
    },
    "signal-agent": {"signal-event", "signal-protocol", "signal-collector-sdk"},
    "signalctl": {"signal-protocol"},
}


def main():
    output = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked", "--offline"],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=30,
    )
    metadata = json.loads(output.stdout)
    members = set(metadata["workspace_members"])
    packages = [p for p in metadata["packages"] if p["id"] in members]
    names = {p["name"] for p in packages}
    if names != set(ALLOWED):
        raise SystemExit(f"Unexpected workspace membership: {sorted(names ^ set(ALLOWED))}")
    for package in packages:
        local = {d["name"] for d in package["dependencies"] if d["name"] in names}
        invalid = local - ALLOWED[package["name"]]
        if invalid:
            raise SystemExit(f"Invalid dependency direction: {package['name']} -> {sorted(invalid)}")
        src = Path(package["manifest_path"]).parent / "src"
        for path in src.rglob("*.rs"):
            text = path.read_text()
            if re.search(r"\bdemo\.|\bunbounded_channel\s*\(", text):
                raise SystemExit(f"Company namespace or unbounded channel: {path.relative_to(ROOT)}")
    print(f"Workspace boundaries verified: {len(packages)} packages; no reverse dependencies")


if __name__ == "__main__":
    main()

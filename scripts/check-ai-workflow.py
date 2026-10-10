#!/usr/bin/env python3
"""Check compact current pages and byte-exact historical snapshots."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def check(root=ROOT):
    manifest = json.loads((root / 'docs/ai-history-index.json').read_text())
    for entry in manifest['snapshots']:
        historical = (root / 'docs' / entry['archive']).read_bytes()
        assert len(historical) == entry['bytes'], entry['archive']
        assert hashlib.sha256(historical).hexdigest() == entry['sha256'], entry['archive']
        current = (root / 'docs' / entry['current']).read_text()
        assert len(current.splitlines()) <= 300, entry['current']
        assert entry['archive'] in current, entry['current']
        for slug in entry['headings']:
            # Either a compatibility anchor or a retained ordinary heading.
            if f'id="{slug}"' not in current:
                assert any(re.sub(r'[^\w -]', '', line.lstrip('# ').lower()).replace(' ', '-') == slug
                           for line in current.splitlines() if line.startswith('#')), slug
    assert (root / 'docs/49-ai-execution-workflow.md').is_file()
    print('AI workflow: 3 exact historical snapshots, compact current pages and heading redirects passed')


if __name__ == '__main__':
    check()

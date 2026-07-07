#!/usr/bin/env bash
# Render every NN-*.mmd to dist/NN-*.svg (portable: no foreignObject) and, with PNG=1, dist/NN-*.png.
# Requires Node.js and a Chromium that Puppeteer can download. Pinned CLI for reproducible output.
set -euo pipefail
cd "$(dirname "$0")"
MMDC="npx --yes @mermaid-js/mermaid-cli@11.4.2"
mkdir -p dist
for f in [0-9][0-9]-*.mmd; do
  n="${f%.mmd}"
  $MMDC -q -i "$f" -o "dist/$n.svg" -c mermaid.config.json -p puppeteer.json -b white -I "sig-${n#??-}"
  if [ "${PNG:-0}" = 1 ]; then
    $MMDC -q -i "$f" -o "dist/$n.png" -c mermaid.config.json -p puppeteer.json -b white -s 3
  fi
done
ls -l dist

#!/usr/bin/env bash
# Usage: ./demo.sh up|down|inject <scenario>|findings|events|stats|crash|private on|off|replay|live|notify|webhook-logs
set -euo pipefail
cd "$(dirname "$0")"
TOKEN_FILE=".token"
[ -f "$TOKEN_FILE" ] || { umask 077; openssl rand -hex 24 > "$TOKEN_FILE"; }
export SIGNAL_API_TOKEN="$(cat "$TOKEN_FILE")"
BASE="http://127.0.0.1:${SIGNAL_HTTP_PORT:-8080}"
OVERLAY="${PRIVATE_OVERLAY_DIR:-../../../platform-signal-private/overlays/example}"
dc() { if [ -f .private-on ]; then docker compose -f compose.yaml -f compose.private.yaml "$@"; else docker compose "$@"; fi; }
api() { curl -fsS -H "authorization: Bearer $SIGNAL_API_TOKEN" "$BASE$1"; }
case "${1:-}" in
  up)   dc up -d --no-build
        until curl -fs "$BASE/readyz" >/dev/null; do sleep 1; done
        echo "ready: $BASE/ui   token in examples/demo/.token" ;;
  down) dc down ${2:-}; [ "${2:-}" = "-v" ] && rm -rf .outbox || true ;;
  inject) dc run --rm --no-deps billing-api python /emitter.py --mode http --only "${2:?brute-force|priv-grant|export|tamper}" ;;
  findings) api "/v1/findings?limit=${2:-20}" | python3 -m json.tool ;;
  events)   shift; api "/v1/events?order=desc&limit=10${1:+&$1}" | python3 -m json.tool ;;
  stats)    curl -fsS "http://127.0.0.1:${SIGNAL_METRICS_PORT:-9090}/metrics" | grep -E 'signal_(ingest|queue|wal|findings)' | head -30 ;;
  crash)    dc kill -s KILL signal; dc up -d signal ;;
  private) case "${2:-}" in
      on)  [ -d "$OVERLAY/rules/security" ] || { echo "overlay not found: $OVERLAY" >&2; exit 1; }
           touch .private-on ;;
      off) rm -f .private-on ;;
      *)   echo "usage: $0 private on|off" >&2; exit 1 ;;
    esac
    dc up -d --no-build --force-recreate signal
    until curl -fs "$BASE/readyz" >/dev/null; do sleep 1; done
    echo "private rules: $([ -f .private-on ] && echo ON || echo OFF)" ;;
  replay) # the overlay's raw event, then the same event after overlay enrichment
    for f in input/security-event.json expected/enriched-security-event.json; do
      python3 - "$OVERLAY/fixtures/$f" <<'PY' | curl -fsS -H "authorization: Bearer $SIGNAL_API_TOKEN" -H 'content-type: application/json' -d @- "$BASE/v1/events" >/dev/null
import json, sys, uuid, datetime
e = json.load(open(sys.argv[1]))
e["id"] = str(uuid.uuid4())
e["timestamp"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
e.pop("observed_at", None)
print(json.dumps(e))
PY
      echo "sent $f"
    done ;;
  live) # raw events -> private overlay enricher (real SDK code) -> Signal
    BIN="${OVERLAY_ENRICH_BIN:-$OVERLAY/../../target/debug/signal-enrich}"
    [ -x "$BIN" ] || { echo "build it: (cd $OVERLAY/../.. && cargo build --bin signal-enrich)" >&2; exit 1; }
    python3 - "$OVERLAY/fixtures/input/security-event.json" <<'PY' |
import json, sys, uuid, datetime
base = json.load(open(sys.argv[1]))
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
for action in ["iam:CreateUser", "iam:CreateAccessKey", "s3:ListBuckets"]:
    e = json.loads(json.dumps(base))
    e["id"], e["timestamp"], e["observed_at"] = str(uuid.uuid4()), now, now
    e["attributes"]["event"]["action"] = action
    e["message"] = "raw cloudtrail: " + action
    print(json.dumps(e))
PY
    SIGNAL_OVERLAY_PATH="$(cd "$OVERLAY" && pwd)" "$BIN" |
    python3 -c 'import sys,json; print(json.dumps({"events":[json.loads(l) for l in sys.stdin]}))' |
    curl -fsS -H "authorization: Bearer $SIGNAL_API_TOKEN" -H 'content-type: application/json' -d @- "$BASE/v1/events/batch" |
    python3 -c 'import sys,json; r=json.load(sys.stdin); print("enriched and accepted:", r["accepted"])' ;;
  notify) # private outbox: findings feed -> routing policy -> webhook (add --watch to keep running)
    BIN="${OVERLAY_NOTIFY_BIN:-$OVERLAY/../../target/debug/signal-notify}"
    [ -x "$BIN" ] || { echo "build it: (cd $OVERLAY/../.. && cargo build --bin signal-notify)" >&2; exit 1; }
    SIGNAL_URL="$BASE" NOTIFY_DIR="$PWD/.outbox" "$BIN" $([ "${2:-}" = "--watch" ] || echo --once) ;;
  webhook-logs) dc logs --no-log-prefix --tail "${2:-20}" webhook ;;
  *) sed -n 2p "$0"; exit 1 ;;
esac

"""Demo log emitter: mostly normal traffic with injected security scenarios.

--mode http  POST batches to /v1/events/batch (an app using the HTTP API directly)
--mode file  append JSON lines to a file (a legacy app; signal-agent tails it)
"""
import argparse, json, os, random, time, urllib.request
from datetime import datetime, timezone

USERS = ["alice", "bob", "carol", "dave"]
NORMAL_IPS = ["10.0.1.11", "10.0.1.12", "10.0.2.7"]
ATTACKER = "203.0.113.66"


def ev(message, action, outcome="success", sev="info", user=None, ip=None, **extra):
    attrs = {"event": {"action": action, "outcome": outcome}}
    if user:
        attrs["user"] = {"name": user}
    if ip:
        attrs["client"] = {"ip": ip}
    attrs.update(extra)
    return {"message": message, "severity": sev, "attributes": attrs}


def normal():
    u, ip = random.choice(USERS), random.choice(NORMAL_IPS)
    return random.choice([
        ev(f"GET /orders 200", "http.request", user=u, ip=ip),
        ev(f"login ok for {u}", "auth.login", user=u, ip=ip),
        ev(f"GET /health 200", "http.request", ip=ip),
    ])


def scenario(name):
    if name == "brute-force":
        return [ev("login failed for admin", "auth.login", "failure", "warn", "admin", ATTACKER)
                for _ in range(6)] + [ev("login ok for admin", "auth.login", user="admin", ip=ATTACKER)]
    if name == "priv-grant":
        return [ev("role admin granted to bob", "role.grant", sev="warn", user="admin", ip=ATTACKER,
                   target={"user": "bob", "role": "admin"})]
    if name == "export":
        return [ev("export of customer table", "data.export", sev="warn", user="bob", ip=ATTACKER,
                   data={"classification": "sensitive", "rows": 48210})]
    if name == "tamper":
        return [ev("audit trail disabled", "audit.disable", sev="error", user="admin", ip=ATTACKER)]
    return []


SCENARIOS = ["brute-force", "priv-grant", "export", "tamper"]


def stamp(e, args):
    e["timestamp"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if args.mode == "http":
        e["source"] = {"type": "application", "name": args.name}
    return e


def send(batch, args):
    body = json.dumps({"events": batch}).encode()
    req = urllib.request.Request(args.server.rstrip("/") + "/v1/events/batch", body,
                                 {"content-type": "application/json",
                                  "authorization": "Bearer " + os.environ["SIGNAL_API_TOKEN"]})
    with urllib.request.urlopen(req, timeout=5) as r:
        r.read()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["http", "file"], required=True)
    p.add_argument("--name", default="billing-api")
    p.add_argument("--server", default="http://signal:8080")
    p.add_argument("--file", default="/logs/legacy-app.log")
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--scenario-every", type=int, default=20, help="ticks between injected scenarios")
    p.add_argument("--only", help="inject just this scenario once and exit")
    args = p.parse_args()

    def emit(events):
        events = [stamp(e, args) for e in events]
        if args.mode == "http":
            send(events, args)
        else:
            with open(args.file, "a") as f:
                for e in events:
                    flat = dict(e["attributes"], message=e["message"], level=e["severity"])
                    f.write(json.dumps(flat) + "\n")
        print(f"emitted {len(events)} events", flush=True)

    if args.only:
        emit(scenario(args.only))
        return
    tick, i = 0, 0
    while True:
        tick += 1
        batch = [normal() for _ in range(random.randint(2, 5))]
        if tick % args.scenario_every == 0:
            batch += scenario(SCENARIOS[i % len(SCENARIOS)])
            i += 1
        for attempt in range(30):
            try:
                emit(batch)
                break
            except Exception as exc:  # server not ready yet / restarting
                print("retry:", exc, flush=True)
                time.sleep(1)
        time.sleep(args.interval)


main()

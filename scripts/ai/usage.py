#!/usr/bin/env python3
"""Snapshot local Codex counters for SIGNAL; never query billing or prompt content."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[2]
TOKEN_KEYS = ("input_tokens", "cached_input_tokens", "output_tokens",
              "reasoning_output_tokens", "total_tokens")


def snapshot(codex_home, thread_id=None):
    database = codex_home / "state_5.sqlite"
    with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True,
                         timeout=5) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT id, rollout_path, model, reasoning_effort, tokens_used "
            "FROM threads WHERE cwd = ?" + (" AND id = ?" if thread_id else ""),
            (str(ROOT), thread_id) if thread_id else (str(ROOT),),
        ).fetchall()
    if thread_id and not rows:
        raise ValueError("Thread is not recorded in this project")
    totals = dict.fromkeys(TOKEN_KEYS, 0)
    threads = {}
    unavailable = []
    for row in rows:
        latest = None
        try:
            with Path(row["rollout_path"]).open() as stream:
                for line in stream:
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    payload = event.get("payload", {})
                    if event.get("type") == "event_msg" and payload.get("type") == "token_count":
                        info = payload.get("info")
                        if info and info.get("total_token_usage"):
                            latest = info["total_token_usage"]
        except OSError:
            pass
        if latest is None:
            if row["tokens_used"]:
                unavailable.append(row["id"])
            latest = dict.fromkeys(TOKEN_KEYS, 0)
        counts = {key: latest.get(key, 0) for key in TOKEN_KEYS}
        threads[row["id"]] = {"model_at_snapshot": row["model"],
                              "effort_at_snapshot": row["reasoning_effort"],
                              "tokens": counts}
        for key, value in counts.items():
            totals[key] += value
    return {"schema_version": 1, "captured_at": datetime.now(timezone.utc).isoformat(),
            "project": str(ROOT), "thread_id": thread_id, "tokens": totals,
            "threads": threads, "unavailable_threads": unavailable,
            "scope": "Local Codex telemetry; cached input and reasoning are subsets. "
                     "Project totals include concurrent tasks, delegated work and approval "
                     "reviews. Model labels describe the snapshot, not historical routing. "
                     "This is not billing or included-allowance accounting."}


def compare(current, baseline):
    if any(current[key] != baseline[key] for key in ("schema_version", "project", "thread_id")):
        raise ValueError("Baseline schema, project and thread scope must match")
    if current["unavailable_threads"] or baseline["unavailable_threads"]:
        raise ValueError("Cannot compare incomplete token snapshots")
    removed = set(baseline["threads"]) - set(current["threads"])
    if removed:
        raise ValueError("Baseline threads disappeared; counters are not comparable")
    for thread_id, entry in baseline["threads"].items():
        if any(current["threads"][thread_id]["tokens"][key] < entry["tokens"][key]
               for key in TOKEN_KEYS):
            raise ValueError("A thread counter decreased; counters are not comparable")
    elapsed = (datetime.fromisoformat(current["captured_at"]) -
               datetime.fromisoformat(baseline["captured_at"])).total_seconds()
    if elapsed < 0:
        raise ValueError("Baseline capture time is after the current snapshot")
    return {"elapsed_seconds": round(elapsed, 3),
            "tokens": {key: current["tokens"][key] - baseline["tokens"][key]
                       for key in TOKEN_KEYS},
            "new_threads": len(set(current["threads"]) - set(baseline["threads"]))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="Write a new JSON snapshot (refuses to overwrite)")
    parser.add_argument("--baseline", type=Path, help="Compare with an earlier snapshot")
    parser.add_argument("--thread-id", help="Limit telemetry to one project thread")
    parser.add_argument("--codex-home", type=Path, default=Path.home() / ".codex",
                        help="Local Codex data directory")
    args = parser.parse_args()
    try:
        result = snapshot(args.codex_home, args.thread_id)
        if args.baseline:
            result["delta"] = compare(result, json.loads(args.baseline.read_text()))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"snapshot": str(args.output), "tokens": result["tokens"],
                          "unavailable_threads": len(result["unavailable_threads"]),
                          "delta": result.get("delta")}, indent=2))
    except (OSError, sqlite3.Error, ValueError, KeyError) as error:
        print(f"Usage snapshot failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

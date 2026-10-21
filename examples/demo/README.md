# Signal demo stack

Local Compose demo: two log sources feed `signal-server`; query results in the UI
at `http://127.0.0.1:8080/ui` (token in `.token`, created by `./demo.sh up`).

| Source | Path into Signal |
| --- | --- |
| `billing-api` | HTTP `POST /v1/events/batch` |
| `legacy-app` | writes a log file, tailed by `signal-agent` (durable spool) |

```bash
./demo.sh up                  # start everything
./demo.sh inject brute-force  # brute-force | priv-grant | export | tamper
./demo.sh findings            # / events [query] / stats
./demo.sh crash               # SIGKILL the server; admitted events replay from the WAL
./demo.sh down -v             # stop and reset
```

## OSS core vs. private overlay

Requires the sibling `platform-signal-private` checkout (override with
`PRIVATE_OVERLAY_DIR`). Its rules are mounted read-only at runtime; nothing is copied here.

```bash
./demo.sh private off && ./demo.sh replay   # no finding for the overlay's CloudTrail events
./demo.sh private on  && ./demo.sh replay   # only the overlay-enriched event matches the private rule
```

`replay` sends the overlay's raw event and the same event after overlay enrichment.
Enrichment itself runs in the overlay process, not in the server.

### Live enrichment

`./demo.sh live` takes raw CloudTrail-style events, runs them through the overlay's real
enricher (`signal-enrich`, a small binary in the private repo that reads events on stdin)
and posts the result to Signal. Build it once:
`(cd ../../../platform-signal-private && cargo build --bin signal-enrich)`.
With `private on`, the privileged actions (`iam:CreateUser`, `iam:CreateAccessKey`) raise
the private finding; `s3:ListBuckets` is enriched and stored but raises nothing.

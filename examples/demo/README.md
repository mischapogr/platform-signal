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

### Notifications through the private outbox

`./demo.sh notify` runs `signal-notify` (private repo; build with
`cargo build --bin signal-notify`). It reads the public `GET /v1/findings/feed`, commits
each page plus its delivery plan in one transaction to a local SQLite outbox
(`.outbox/`), applies the private routing policy (high and critical go to the
webhook) and sends with a stable `Idempotency-Key`. `./demo.sh webhook-logs` shows what
the receiver got. Start the stack with `WEBHOOK_FAIL_FIRST=2 ./demo.sh up` to see 503s
retried with the same key. Re-running `notify` only plans findings newer than the
stored cursor. `./demo.sh notify --watch` keeps polling.

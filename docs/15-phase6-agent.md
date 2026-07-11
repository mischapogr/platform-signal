# Phase 6 — Edge agent

`signal-agent` reads newline-delimited stdin or configured regular files, converts
each line to the canonical event contract, durably spools events, and forwards
batches to `signal-server`. This document records the implemented interface and
failure behavior. Phase 6 passed its local Linux AMD64 build, workspace,
process, and independent-review gates. The evidence and platform limits are
recorded below and in [07-progress.md](07-progress.md).

## Native transport security

`SIGNAL_AGENT_TLS_CONFIG` selects a bounded private version1 identity/roots/CRLs
file and requires HTTPS. Explicit roots replace ambient trust; stock Rustls checks
peer chain, hostname, time and supplied signed CRLs. Original request deadlines
also cover ready-response handoff; uncertainty retains spool IDs. Fixed physical
configuration/DNS workers retain their capacity after caller cancellation/expiry.
Stopped/restart replacement rotates trust/identity without changing original
spool/source cursors. See [transport contract](44-transport-security.md) and current
acceptance in [progress](07-progress.md). This native slice does not yet qualify
protected packaging probes, collector publishing, real PKI or external releases.

## Input contract

Each agent process accepts at most 16 inputs. With no `--file` or `--stdin`, it
reads stdin. Stdin is Linux `/proc/self/fd/0`, opened nonblocking; it has no
durable source cursor. A stdin line is held in memory until its event or skip is
admitted to the spool, but a process crash before that admission can lose input
already read from the pipe.

File inputs must be regular files and are opened without following symlinks.
The agent follows the configured path by default. It remembers a file cursor as
input number, device, inode, byte offset, and up to 64 preceding bytes. On
restart, it resumes only if the configured file still has the same identity and
the anchor matches; otherwise it starts at offset zero. Copy-truncate or changed
content at the cursor resets the reader to zero. Rotation is detected while the
process runs by reopening the configured path. The agent does not discover an
old rotated pathname after restart. Unspooled bytes remaining in a renamed file,
including bytes written before a crash, can be missed after restart. Configure
the rotated path separately if it must be collected.

Input is split on LF, with a trailing CR removed. Blank, invalid UTF-8, malformed
JSON in JSON parsing modes, and over-limit lines are skipped and counted. A
partial line remains buffered until LF; stdin EOF and `--once` flush a final
nonempty partial line. File following waits for additional bytes. The line
buffer is bounded by the configured limit (default 65,536 bytes; maximum
65,536).

`--format auto` parses a line beginning with `{` as JSON; malformed or
non-object JSON is rejected. Other lines are plain text. `json` requires every
line to be a JSON object. `plain` always treats the line as a message. For JSON
objects, all keys are preserved in `attributes`; a string-valued `message` key
also supplies the canonical event message, otherwise the whole line is the
message. The event uses the configured
source (default type `log`), `info` severity, empty tags and no resource or trace
IDs. It generates a UUID and sets `timestamp` and `observed_at` to the current
UTC time. Events that exceed the canonical event byte limit (default 65,536;
maximum 1 MiB) are counted and skipped without stalling ingestion. For a file,
the cursor for a skipped line is durably checkpointed, so the line is not
retried after restart.

## CLI and environment

CLI values override their matching environment values. Token configuration is
environment-only. Durations are milliseconds. Numeric settings are validated
before workers start.

| CLI option | Environment variable | Default | Accepted range / behavior |
| --- | --- | ---: | --- |
| `--server` | `SIGNAL_AGENT_SERVER` | `http://127.0.0.1:8080` | HTTP(S) server URL; batch endpoint is `/v1/events/batch` |
| `--file PATH` | — | none | Repeatable; at most 16 inputs total; regular file only |
| `--stdin` | — | implicit when no inputs | At most once; Linux stdin input |
| `--once` | — | follow files | Read files to current EOF and stop |
| `--spool-dir PATH` | `SIGNAL_AGENT_SPOOL_DIR` | `data/agent-spool` | Dedicated, exclusively locked spool directory |
| `--format auto\|plain\|json` | `SIGNAL_AGENT_FORMAT` | `auto` | Input parsing mode |
| `--source-type TYPE` | `SIGNAL_AGENT_SOURCE_TYPE` | `log` | Nonempty, at most 256 bytes |
| `--source-name NAME` | `SIGNAL_AGENT_SOURCE_NAME` | none | Optional, nonempty, at most 256 bytes |
| `--batch-events N` | `SIGNAL_AGENT_BATCH_EVENTS` | 100 | 1–1,000 events |
| `--batch-bytes N` | `SIGNAL_AGENT_BATCH_BYTES` | 1,048,576 | 4 KiB–16 MiB HTTP body |
| `--flush-ms N` | `SIGNAL_AGENT_FLUSH_MS` | 1,000 | 1–60,000 ms |
| `--request-timeout-ms N` | `SIGNAL_AGENT_REQUEST_TIMEOUT_MS` | 5,000 | 1–60,000 ms |
| `--retry-base-ms N` | `SIGNAL_AGENT_RETRY_BASE_MS` | 100 | 1–60,000 ms; cannot exceed retry cap |
| `--retry-max-ms N` | `SIGNAL_AGENT_RETRY_MAX_MS` | 5,000 | 1–60,000 ms |
| `--shutdown-timeout-ms N` | `SIGNAL_AGENT_SHUTDOWN_TIMEOUT_MS` | 10,000 | 1–60,000 ms |
| `--max-spool-bytes N` | `SIGNAL_AGENT_MAX_SPOOL_BYTES` | 67,108,864 | 32 KiB–1 GiB configured logical disk limit |
| `--max-spool-events N` | `SIGNAL_AGENT_MAX_SPOOL_EVENTS` | 10,000 | 1–100,000 records |
| `--max-line-bytes N` | `SIGNAL_AGENT_MAX_LINE_BYTES` | 65,536 | 1–65,536 bytes |
| `--max-event-bytes N` | `SIGNAL_AGENT_MAX_EVENT_BYTES` | 65,536 | 1 KiB–1 MiB canonical event JSON |
| `--metrics-listen ADDRESS` | `SIGNAL_AGENT_METRICS_LISTEN` | disabled | Optional address; one sequential connection at a time |
| — | `SIGNAL_AGENT_API_TOKEN` | unset | Optional Bearer token; environment only |

The batch byte setting includes the HTTP JSON envelope. Configuration requires
an event to fit the batch envelope. The spool also has bounded command and
operation queues and a bounded record index. Its disk quota charges logical
record bytes plus a 16 KiB metadata reserve covering state, temporary files,
and lock metadata. The largest configured event record must fit in an empty
spool after that reserve, 512 bytes of cursor overhead, and the 12-byte record
frame; invalid combinations fail configuration. This is not a process RSS or
physical filesystem block/inode quota. The record count and index-byte limits
separately bound record and index overhead. The input workers and disk worker
use ordinary threads for filesystem/pipe operations. Deadlines and cancellation
bound the callers and admission; an in-progress kernel I/O operation cannot be
physically cancelled. A timed-out or cancelled spool operation closes spool
admission while its operation permit remains held until physical work completes.

The optional metrics listener serves `GET /metrics` only. It handles one
connection at a time, reads at most 1 KiB of request data, and gives the request
two seconds. It exposes bounded spool, input, retry, rejection, and request
counters; it is a small built-in listener, not a general HTTP server.

## Spool, retry, and shutdown semantics

The local spool is single-owner and durable. Framed records carry sequence and
CRC checks; recovery may truncate only an incomplete, uncommitted final record.
A missing or truncated committed record, complete corruption, or sequence gap
fails closed. File cursor state is atomically replaced and directory-synced
before acknowledged spool files are removed. Spool quota exhaustion pauses new
input admission and retries after a short delay while forwarding continues. It
does not intentionally discard a valid event to make room. A fail-closed spool or filesystem error terminates the
agent with pending records retained where possible.

The sender verifies response schema, event IDs and accepted-prefix accounting.
It acknowledges only the prefix the server explicitly reports accepted, then
retries the remaining suffix. Retryable overload, timeout, and unavailable
responses use capped exponential backoff with jitter. An invalid, lost, or
timed-out response leaves the local batch unacknowledged and may cause already
accepted events to be sent again. Event IDs survive spool recovery, but the
delivery contract is at least once: duplicates are possible and exactly-once
delivery is not claimed.

SIGTERM or Ctrl-C stops source reads, allows an already-started spool admission
to finish, then drains the spool using one shutdown deadline. At that deadline
the runtime cancels logical work and returns failure with pending records kept
for restart where possible. Ordinary worker threads cannot forcibly interrupt a
kernel read/write already in progress. A clean success requires an empty spool.

## Local run

Build both executables before running the agent process gate:

```bash
cargo build -p signal-server -p signal-agent
```

Example: read a file and stdin while retaining the spool between restarts. When
server authentication is enabled, provide `SIGNAL_AGENT_API_TOKEN` through the
runtime's secret environment; do not put it in command arguments.

```bash
cargo run -p signal-agent -- --server http://127.0.0.1:8080 \
  --file /var/log/example.log --stdin --spool-dir ./data/agent-spool
```

Query the resulting persisted events using the server's
[event query API](13-phase4-query.md). The server must be independently running.
The process gate and workspace/independent review evidence are recorded in
[07-progress.md](07-progress.md).

## Phase 6 verification

| Check | Result |
| --- | --- |
| `cargo build --workspace --locked` | Passed |
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo test --workspace` | Passed: 203 tests, including 36 agent library tests (19 spool, 7 input, 8 HTTP, 1 config, 1 runtime) and 1 agent process test; prior 166-test workspace coverage retained |
| `python3 scripts/check-workspace.py` | Passed: 12 packages and dependency/source boundaries |
| Agent process gate | Passed offline in 4.61 s on Linux AMD64. Covered spool quota and SIGKILL recovery through the 13th append; authentication/token redaction; across spool quota, one server-accepted event and one canonical oversize rejection without rereading; stdin large integers; file partial lines, rename rotation, copy-truncate, idle follow, SIGTERM, and server restart |
| Spool directory bootstrap | New spool directory uses mode 0700. Initial bootstrap syncs the bounded parent chain (at most 128 components / 4,096 bytes), including pre-existing empty ancestor directories, before state publication |
| Independent review | Final 14-area review closed all high findings and approved the source |

These results establish local Linux AMD64 behavior only. ARM64, process RSS,
an agent container build, and actual power-loss tests were not run. Source-ordering
checks are not power-loss proof. Phase 6 completion does not complete the full
`v0.1.0` release gate or the external Phase 7 overlay proof.

The 203-test count above is the historical Phase 6 acceptance run. The current
root workspace gate after Phase 7 SDK and WAL recovery work passed 212 tests;
see [current progress](07-progress.md).

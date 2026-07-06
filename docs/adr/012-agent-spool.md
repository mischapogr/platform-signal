# ADR-012: Durable edge-agent spool and source cursors

**Status:** Implemented and locally accepted on Linux AMD64 under the supplied
Phase 6 specification.

**Phase:** 6

## Context

The edge process must tolerate server outages and process restarts without
turning an unbounded memory queue into its backlog. File inputs also need a
restart position that advances only after the corresponding event or rejected
line has been durably handled. HTTP admission can be uncertain when a request
or response is interrupted, so retry must preserve event identity and permit
duplicates.

## Decision

- `signal-agent` reads bounded newline-delimited stdin and configured regular
  files. Input count, line bytes, event bytes, spool disk/record/index limits,
  in-flight work, batch size and HTTP response bytes are bounded.
- A versioned, CRC-framed local spool is single-owner and persists event records
  and file source cursors. A file cursor identifies the input slot, device,
  inode, byte offset and up to 64 preceding anchor bytes. A valid event is
  appended with its next cursor; a skipped/oversized line advances a durable
  file cursor through a checkpoint record. Cursor state is synced before acked
  spool records are reclaimed. Initial directory bootstrap creates the new
  spool directory with mode 0700 and syncs its bounded parent chain (up to 128
  path components / 4,096 bytes), including pre-existing empty ancestors,
  before publishing state.
- Only regular files are followed. Rotation is detected by reopening the
  configured path while running. The process does not search for old rotated
  paths after restart. Unspooled bytes remaining in a renamed file, including
  bytes written before a crash, can be missed after restart. Stdin is read from
  Linux `/proc/self/fd/0` and has no durable source cursor.
- Spool quota/capacity pressure pauses source admission and allows forwarding
  to free space. Corruption, closed spool, or I/O failure is fail-closed. The
  quota charges logical record bytes plus a 16 KiB metadata reserve covering
  state, temporary files, and lock metadata. The largest configured record
  must fit an empty spool after this reserve, 512 bytes of cursor overhead, and
  its 12-byte frame. Record and index limits separately constrain overhead.
  These are not process RSS or physical filesystem block limits. Recovery may
  truncate only an incomplete, uncommitted final record; missing or truncated
  committed records fail closed.
- The sender acknowledges only the explicitly verified HTTP accepted prefix.
  It retries the suffix with capped exponential backoff and jitter. When
  transport or response status is uncertain, it retains the batch and retries
  with the same event IDs. Delivery is at least once and may contain
  duplicates; exactly-once delivery is not promised.
- Shutdown stops source reads, permits an already-started append to complete,
  and drains to a shared deadline. Cancellation bounds callers and admission,
  but ordinary worker threads cannot physically cancel a kernel I/O operation
  already in progress. Pending spool records remain for restart where possible.
- API authentication uses only `SIGNAL_AGENT_API_TOKEN`; token-bearing values
  are not included in diagnostics. Optional metrics use a bounded sequential
  listener.

## Consequences

An acknowledged server prefix is not retransmitted in the normal partial-batch
path. Uncertain commits can be delivered more than once, so downstream event
identity remains important. File restart resumption depends on the configured
path still naming the same inode and matching its anchor. Rotation while the
agent is stopped can leave unspooled bytes in the old file undiscovered. Stdin
cannot recover bytes lost before spool admission. Operators must size and retain
the local spool and configure file paths accordingly.

## Verification

The local Linux AMD64 gate passed workspace build, formatting, Clippy, 203
workspace tests, the 12-package boundary check, a 4.61-second offline
agent-to-server process gate, and an independent final 14-area review with all
high findings closed. This does not prove ARM64 behavior, process RSS, an agent
container build, or actual power-loss behavior. Source-ordering checks are not
power-loss proof. See [Phase 6 agent contract](../15-phase6-agent.md) and
[implementation progress](../07-progress.md).

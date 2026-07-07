# Finding contract and journal

`Finding::for_event(rule_id, event, severity, title)` uses UUIDv5 over a fixed
public namespace, an eight-byte rule-ID length, UTF-8 rule ID and raw event UUID.
It uses `event.observed_at`; it never reads the clock. Replay with equal content
is accepted once. Changed content for the same finding ID is a conflict.
Detection severity is `low`, `medium`, `high` or `critical`.

`FindingStore::open(config, stream_id)` validates configuration, locks the root
and binds it to the WAL stream UUID. Unknown entries, symlinks, a second writer,
corrupt records or a different stream refuse startup. `findings.journal` has a
24-byte magic/stream header and 12-byte length/payload-CRC32/header-CRC32 framed JSON records. The initial
header is written and synced in `findings.journal.tmp`, renamed and directory
synced. An unfinished header temporary can be recovered only when no final
journal exists; a corrupt final header always refuses startup. Only an
incomplete final frame is truncated and synced. The length and payload CRC are authenticated by the header CRC before any
incomplete-payload classification. Complete checksum failures
remain fatal. No finding retention or deletion policy is implemented.

`append(Vec<Finding>, FindingContext)` validates the entire bounded batch and
checks conflicts, disk, row and index quotas before mutation. The batch is
synced once before a receipt reports inserted/duplicate counts. After uncertain
mutation the store fails closed; restart restores the index from the journal.
Repeated ingestion can recover partially completed batches through deterministic
finding IDs. The coordinated consumer must acknowledge WAL only after both
required stores have returned their durable receipts.

`query(FindingQuery, FindingContext)` supports `[from,to)`, severity, rule ID and
a mandatory limit, ordered ascending by `(created_at, id)`. It scans the time
index without collecting all IDs. The response budget conservatively charges
64 times serialized record bytes plus the finding struct for decoded JSON,
vector spare capacity and transient record memory; the configured byte value
therefore bounds memory more strictly than JSON wire bytes. A filtered record
is separately bounded to 64 KiB, 32 JSON levels and 4096 nodes. Timestamp years
are 0000 through 9999; canonical event leap seconds are preserved.

One ordinary disk thread owns all filesystem work. A single reserved control slot wakes shutdown independently of data permits.
Bounded channel admission and
shared semaphore permits account for queued, active and completed but unpolled
responses. Dropping or timing out a request cancels its child token; an active
mutation also fails closed. A read timeout keeps append healthy. Disk syscalls
cannot be interrupted: the tracked worker retains its permit and root lock until
the syscall returns. `shutdown(context)` stops dispatch and waits only until the
supplied deadline; dropping a store never joins the worker on a Tokio thread.
Applications should finish coordinated consumption and call `flush(context)`
before shutdown. An expired shutdown leaves pending WAL records replayable.

Default limits: journal 256 MiB; 100,000 findings; index 16 MiB with conservative
256-byte charges per indexed finding; record 64 KiB; append 1000 rows/1 MiB;
query 1000 rows/8 MiB conservative memory; eight operations; five-second maximum
operation time. The first reached quota wins (the default index admits 65,536
findings). Configuration has finite hard ceilings. Metrics expose finding count,
journal bytes, charged index bytes, operation depth/capacity, rejections,
timeouts, failures and closed state. Counters are process-local.

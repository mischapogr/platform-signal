# Bounded CloudTrail object reading and preparation

OBJECT-READER contract, following local receipt recovery. The reader and preparation substeps are
accepted with 461 workspace tests and independent review. Parsing
does not grant source access, attest completeness or authorize ACK. Current
capture/version/discovery/binding authority and custody remain application duties.

The reader accepts one bounded compressed input (8 MiB) and a finite operation
context. Read one gzip member in bounded chunks; verify CRC/ISIZE and reject any
remaining input, including concatenated members. Cap decoded bytes at 32 MiB.
Parse exactly one Records array, with native spans excluding separator whitespace,
at most 1,024 entries and 256 KiB per entry. Strict native JSON checks apply to
every entry (duplicate keys, UTF-8, finite numbers, depth/nodes). The complete
object depth limit of 16 includes the outer object and Records array, leaving
14 levels in each native entry; hold the result
until the entire object and trailer pass. Do not retain a whole-object DOM.

The owned decoded buffer/native spans and actual compressed digest provide the
input to pinned whole-object normalization/receipt encoding. Invalid object or
compression requires a separately retained bounded quarantine receipt where
capture succeeded; capture/quota/time failures preserve source responsibility.
No malformed later record may expose an earlier preparation prefix.

Preparation pins receipt/event IDs, capture/preparation time, normalizer
revision, exact original/version/discovery and full binding/retention; compute
all spans/native hashes/dispositions/metadata and encoded-event mappings from
actual bytes. Encoded receipts must execute the existing immutable decoder before
being offered to the store. Replay uses retained preparation rather than generating
new IDs or applying a new normalizer. Quarantine ACK stays blocked in this slice.

Context7 flate2 documentation was checked for single-member `bufread::GzDecoder`,
CRC/ISIZE validation and precise remaining input; implementation uses the already
locked version 1.1.10 with its existing zlib-rs backend as a direct SDK dependency. No new dependency version selected.
Tests must execute corrupt/truncated/trailing/member/limit and native-span cases;
documentation alone does not qualify decompression or source delivery.

Preparation uses trusted in-memory `ReceiptPreparation`, `OriginalCapture` and
`ReceiptRetention` inputs; these have no wire deserialization or credentials.
Caller-supplied non-nil unique event IDs map native ordinals. Count mismatch and
invalid capture/binding/time/retention pins reject. Original-only quarantine retains
actual bytes/digest with zero emitted frames; its decoded length is unknown (zero)
when complete decoding could not be established. Replay never calls the preparer.

Event-v1 timestamps keep their accepted RFC3339 representation. Observation pins
compare parsed instants with canonical metadata time; the normalizer's existing
AutoSi output can omit zero fractional digits. No old event payload is rewritten.

Seven preparation regressions execute deterministic fixture framing and every native
span/hash/ID, malformed-late/original-only quarantine, invalid capture/IDs/scope/
retention, exact publication/reopen bytes with blocked quarantine ACK, equivalent
whole/micro/nanosecond observation times and offset representations, a 1 ns mismatch,
record/count bounds and the 16 MiB aggregate prepared-payload cap. No prefix is
exposed when aggregate bounds quarantine the object. Evidence:
`target/goal-execution-20261007/OBJECT-READER/validation.json` and
`preparation-independent-review.json`. AWS delivery is the next ledger item.

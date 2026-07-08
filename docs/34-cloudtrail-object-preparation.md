# Bounded CloudTrail object reading and preparation

OBJECT-READER contract, following local receipt recovery. The reader substep is
accepted with 454 workspace tests and independent review; preparation is next. Parsing
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

Preparation will pin receipt/event IDs, capture/preparation time, normalizer
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

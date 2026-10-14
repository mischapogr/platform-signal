# Site syslog and selected FortiGate profile

The selected SYSLOG receiver passes local simulated acceptance, recorded in
[the current progress](07-progress.md). Actual firmware/device coverage and
site-loss qualification remain separate external boundaries. The selected initial
parser is `fortigate-default-ns` revision `v1`; agent file/stdin mode `fortigate`
uses the existing durable spool and file cursor. This mode does not open a syslog
listener. UDP is legacy best effort and cannot establish durable delivery.

`syslog::OctetDecoder` selects RFC6587 octet counting explicitly: a nonzero
ASCII decimal length, space, then exactly that many bytes. Leading zeros,
lengths over 64KiB, malformed headers and incomplete EOF fail the connection;
there is no heuristic resynchronization or delimiter fallback. One complete
frame is returned at a time, with the consumed input count; callers retain the
unconsumed suffix. A pending frame is bounded, with no completed-frame queue.
Byte lengths preserve UTF8 and embedded newlines. Receiver integration must
count framing refusals, expose depth/capacity, and bound connections and each
read/handshake with original cancellation/deadline semantics.

The FortiGate projection accepts optional PRI0–191 followed directly by default
key/value payload. RFC3164/RFC5424 headers, CEF and CSV are outside this selected
revision. It requires `devid`, `eventtime`, `logid`, `type`, `subtype` and `level`.
`eventtime` is explicitly unsigned nanoseconds, not guessed from magnitude;
other firmware/time units need their own selected profile. Quoted UTF8 values,
escaped quote/backslash and unquoted values are supported; duplicates, malformed
quotes/escapes, controls, more than256fields and oversized frames fail. Native
fields remain strings under `attributes.fortigate`, separate from canonical
source identity. Obvious credential field names reject the entire record; this
is not a general sensitive-data classifier. Private deployments own authorized
field selection, protected originals and redaction requirements.

Canonical severity maps emergency/alert/critical to critical, error to error,
warning to warn, notice/information to info and debug to debug. Native PRI is
retained separately; its facility/transport header does not override the selected
native severity. Unknown levels fail. Original nanosecond source time and pinned
observed time remain separate. The configured source, never native device ID,
defines the source envelope. Device assertions and client IP are not authentication
or tenant/account authority. Every record declares completeness `not_assessed`.

TCP receipt and TLS success do not acknowledge synced local spooling. A site
receiver must durably own accepted work before advancing its own progress, and
must document pre-spool crash/device buffer/site gateway loss. Replayed spool
records reuse canonical IDs/bytes. No application-level syslog ACK is invented.

Documentation checked2026-10-14: [RFC6587 framing and acknowledgement boundaries](https://www.rfc-editor.org/rfc/rfc6587.html),
[FortiOS7.6.4 Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/3ac31ccf-6656-11f0-a9d0-d2b0d2e22f7d/FortiOS_7.6.4_Log_Reference.pdf),
and [Fortinet native log examples](https://docs.fortinet.com/document/fortiap/latest/fortiwifi-and-fortiap-configuration-guide/855476/configuring-est-and-scep-servers-for-ca-requests).
Selected synthetic fixtures do not qualify actual firmware, device buffers,
TLS identity, full device categories or customer/site coverage.

## Dedicated site receiver

The agent now accepts `--syslog-listen ADDRESS --format fortigate --source-name NAME`
as a dedicated receiver, without file/stdin inputs or `--once`. Plain TCP is
restricted to an explicitly loopback-bound listener and grants no peer identity.
For a remote listener, add `--syslog-tls-config PATH --syslog-peer-sha256 HEX`.
The private TLS document uses the existing version1 DER/base64 material contract.
It requires private roots, mandatory client certificates, validity/signature and
configured revocation checks, with resumption/early data disabled. The exact
SHA256 of the authenticated client leaf is additionally pinned to this configured
source. Root trust alone, native `devid` and client IP do not select source scope.
Certificate rotation requires explicit configuration and restart; there is no
live policy reload or implicit cross-device routing.

One connection is active at a time; extras are closed and counted. Handshakes
have a5second budget. Idle/partial frame reads and spool admission share a fixed
30second frame budget, reset only after a complete record is synced to the local
spool. Frame bytes, pending frame count, connections, capacities and refusals are
exposed at agent metrics. Spool saturation applies bounded backpressure until
that deadline; then the peer is closed and the refusal counted. An incomplete
or rejected frame has no durable-admission promise. Disk/spool failure terminates
the producer rather than continuing to collect without durable ownership.

The existing consumer forwards synced records with original canonical IDs/bytes
through HTTP202/WAL admission. A WAN outage retains the finite local spool;
SIGKILL/restart replays retained records. TCP/TLS has no application-level source
ACK, so a device cannot infer disk sync from socket success. This receiver does
not provide durable raw-original custody, protection from site/host loss, device
buffer recovery or complete source coverage. UDP remains unsupported by this
receiver and explicitly best effort in legacy deployments. Actual firmware and
customer/device identity/coverage remain external qualification requirements.

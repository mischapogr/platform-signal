# Site syslog and selected FortiGate profile

SYSLOG remains pending until the site TCP/TLS receiver, connection identity,
local spool and outage replay are qualified together. The selected initial
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

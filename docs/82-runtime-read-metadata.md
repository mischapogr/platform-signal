# Metadata-only runtime READ profile

D14 implementation contract, not acceptance. Existing Falco open/exec/connect
profiles and their original bytes remain unchanged. A read-capable open is not an
actual successful READ. A JSON whitelist alone does not prove that a sensor did
not capture buffers internally. No credential contents, read-buffer addresses,
iovec contents, command arguments or environment enter this profile.
Records identify the verified native audit ABI. READ/connect include entry-stop
and exit-stop wall-clock bounds; the timestamp is observation/output time, not a
claim of exact kernel operation time. Private historical classification must
cover the entire operation interval. Time-window proofs must account for these
bounds and independently verified clock/order continuity, including regressions.
Capture UUID is part of native and process identity: restarting the collector
must not reuse ordinal or execution-generation identities from an earlier capture.

The reference collector launches only a caller-selected owned child before its
first execution. It never attaches to an existing process. Its initial supported
scope is one native x86_64/ARM64 thread with a private FD table and a static owned
executable. File-backed mmap, pread/readv, splice/sendfile/copy, asynchronous I/O,
cross-process reads, ioctl and recvmsg semantics refuse before execution rather
than silently granting complete read coverage. Dynamic loaders using file-backed
mmap are unsupported in this initial source profile. Fork/clone/vfork,
namespace/FD-table changes, unsupported ABI, signals/restarts or missed stop
pairing terminate capture with an explicit gap/refusal. This scoped process
profile does not establish full-host coverage or physical throughput.

PTRACE_GET_SYSCALL_INFO reports entry/exit type and native ABI; TRACESYSGOOD is
set before syscall stops. The collector has one explicit pending syscall. It
pins regular-file O_PATH metadata at READ entry and holds that reference through
exit. Only actual read with positive return and no error proves bytes read;
EOF/error/open-only/socket reads do not. Begin with read, not unimplemented
pread/readv semantics. Source permission, metadata ambiguity or timeout refuses.

Successful PTRACE_EVENT_EXEC increments a tracer-owned execution generation and
clears pre-exec state. Process boot/PID/start ticks plus generation distinguish
exec and PID reuse. Failed exec never advances that generation. File device,
inode, mount, type and change-time identify the observed object; current paths
are not authority. Private event-time asset and destination policy remains a
separate freshly verified join, never a producer-provided protected/suspicious flag.

The only tracee-memory allowance is bounded sockaddr metadata for connect. READ
and exec handling never dereference user buffers/arguments. Socket addresses are
validated native IPv4/IPv6 metadata; successful connect is a candidate connection,
not evidence of credential transfer. Collector stdout is structured metadata;
tracee stdin/stdout/stderr are isolated so its payload output cannot enter capture.
The collector requires pipe stdout and sets that pipe writer nonblocking; callers
must drain it. Output backpressure terminates capture rather than blocking forever.

Bound tasks, syscall stops, runtime and metadata output; retain counters and
explicit gaps. Cancellation/timeout kills and reaps owned tracees. EXITKILL guards
unexpected tracer death. No global ptrace policy, kernel module, existing user
process or source configuration is changed. Source/capture IDs and configuration
hashes in records are data: consuming hosts authenticate the actual collector,
coverage and current authority before granting admission.

Native qualification must test successful/EOF/failed/invalid-buffer/socket READ,
open-only, FD reuse, successful/rejected exec, unsupported task transitions,
timeout/cancel/reap, address families and successful/failed connect. Distinct
synthetic payload sentinels must be absent from all capture records. Independent
source review checks the memory-access allowlist before actual capture. No native
READ, zero-content, ARM64/CI or release qualification is claimed in advance.

Use the accepted D11 custody/prefix mechanisms for D14 via versioned typed
runtime facts. Preserve D11 schema1 serialization/enrollment/archive compatibility.
D14 must retain exact native/canonical IDs, all contributors, historical asset/
destination/execution decisions, rule/policy/source revisions and original effects
through lateness, expiry, duplicates, pruning and policy-generation handoff.

API documentation was attempted through Context7's Linux man-pages index, which
did not cover the required ptrace request. The official
[ptrace manual](https://man7.org/linux/man-pages/man2/ptrace.2.html) and installed
public headers establish GET_SYSCALL_INFO size/operation/ABI and EXEC semantics.
Neither existing Falco READ buffering nor snaplen0 is qualified as zero-content.

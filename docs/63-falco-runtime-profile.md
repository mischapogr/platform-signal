# Selected Falco syscall metadata and health profile

Implementation in progress, selected on 2026-10-14. HOST-AUTH remains pending.
Synthetic SDK regressions and focused strict Clippy do not establish native
kernel capture, sensor health, full workspace acceptance or release qualification.
`signal-agent --format falco-json --source-name HOST --runtime-boot-id UUID`
selects this projection for file/stdin input. Host and boot are explicit private
bindings; they do not come from native hostname fields. Input/spool/cursor/retry
and rejection limits reuse the existing bounded agent path. Metrics and syscall
records are separate canonical kinds, delivered together with exact spool replay.

The existing [authentication profile](58-host-authentication-profile.md) is a
separate source; file/stdin delivery does not establish runtime coverage.

The selected native sensor is Falco0.44.1 with modern eBPF. This version drops
enter events; deprecated evt.dir cannot distinguish directions and is forbidden. Its source records use
`source: syscall`, RFC3339 `time` and typed `output_fields`. Private deployments
own permissions, kernel capabilities, source/rule configuration, redaction,
identity bindings, original custody and retention. OSS contains the generic
projection and bounded qualification mechanics, not company rules or protected
asset/destination classifications. Native fixture rules will select only owned
test processes and synthetic assets in isolated GitHub runners.

`falco::Profile` binds an explicit configured host ID and nonnil boot UUID.
Record hostname never supplies authority. `proc.pid` and `proc.pid.ts` identify
the process in that host boot, with parent PID/start identity retained. Process
start epoch nanoseconds must be positive and no later than the event; parent
start must not follow child start. PID reuse and host restart remain distinct.
Container/workload relationships are absent until an independently verified
context provider supplies them.

The selected hooks are successful/failed syscall records for execve/execveat,
open/openat/openat2 and connect. Native evt.rawres supplies outcome; evt.rawtime
must exactly agree with native record time. File metadata includes absolute path
and read-capable open flag. A successful open does not prove that material was
read; `actual_read` remains not_assessed. Read/pread records and buffer contents are
excluded from the emitted source profile. Connections retain IP literal and port. Private policy classifies assets
and destinations and determines detections. Native Falco priority and rule names
do not become SIGNAL policy decisions; canonical severity remains Info.

Inputs are bounded to64KiB,256 distinct output fields,16 tags and bounded identity
strings. Syscall output fields have an exact whitelist. Missing/malformed or
duplicate identity fields, unsupported hooks, deprecated direction fields, inconsistent timestamps,
freeform output, command lines, environment and buffer fields refuse. Configure
`json_include_output_property: false` and emit only the selected metadata fields.
Caller-pinned canonical ID and observed time allow retained replay; this pure
projection does not grant durable receipt or checkpoint admission.

Falco evt.num is the native capture event number, not a contiguous sequence of
selected alerts. Gaps can mean filtering; they do not prove loss. Events explicitly
require the separate metrics stream for dropped-event assessment. Every normalized
event retains `runtime_sensor_coverage: not_assessed`. Native source assertions,
configured boot identity and a clean metric sample cannot independently grant
current coverage.

`parse_metrics` selects `source: internal`, rule Falco internal: metrics snapshot
and modern_bpf engine. Native capture time, host boot/start/reload times, captured
count, kernel drops, output queue drops, failed FD/thread lookups, full-threadtable
and store/retrieve drops are required and validated. Missing counters never become
zero. Unknown native metrics are omitted; complete input remains bounded and
fields cannot duplicate. These are source-side assertions. A trusted independent
observer must bind source/configuration/capture hooks, freshness, restart, counter
reset and loss before coverage can be current. Observer failure yields unknown
coverage, never an assumption of no loss.

The local process has no effective kernel capabilities, and Falco is absent.
No local kernel installation or capture is authorized by this profile.
`scripts/check-runtime-sensor.py` enforces an isolated GitHub runner before kernel
capture, pins the multi-architecture Falco image digest and verifies native image
architecture. Only freshly owned synthetic executable rules run; host mounts are
read-only and sensor networking is disabled. Capture has a90second deadline,
2MiB total/64KiB line/512line bounds and owned container/process cleanup.
Actual kernel hooks must appear between native metric samples. The gate then
syncs complete projected events/counters in an offline agent spool, SIGKILLs the
agent, restarts it and verifies exact canonical IDs/values in server query.
`--simulate` selects a distinct delivery-only report and never native acceptance.
CI runs the native gate on both native architectures; matching results are required.
Remaining qualification: current native capture and independent coverage/health
assessment; source counters alone do not become an independent current grant. Full HOST-AUTH acceptance
requires those results; this normalizer is a foundation, not the item's closeout.

Sources checked2026-10-14 through Context7 and current upstream release:
[Falco0.44.1](https://github.com/falcosecurity/falco/releases/tag/0.44.1),
[JSON output](https://falco.org/docs/concepts/outputs/channels/),
[supported syscall fields](https://falco.org/docs/reference/rules/supported-fields/),
[native metrics](https://falco.org/docs/metrics/falco-metrics/),
[modern eBPF container requirements](https://falco.org/docs/setup/container/).

The separate `.github/workflows/runtime-sensor.yml` probe uses its own bounded
queue and builds only the collector SDK after native capture succeeds. It runs
actual capture then an explicitly ignored native-only Rust projection test,
which fails without the owned capture manifest/source/digest binding. This
shortens schema feedback without replacing the full CI agent/server replay gate.
Native capture/projection and full composed acceptance remain distinct.

The native fixture supplies its own minimal Falco configuration and explicit
`-c`/`-r` selection; image config.d plugins and default rules do not supply
fixture behavior. Relative native-test capture paths resolve from the workspace
root, independent of Cargo integration-test working directory. Native capture
failures and their digest-verified artifacts are retained before corrections.

# Independent missing-telemetry detector

SENSOR-HEALTH is in progress. The first slice implements bounded, deterministic
heartbeat assessments; it does not yet install a running detector in Main or
grant durable finding/checkpoint recovery acceptance.

Private configuration pins an expected-source inventory, complete binding digest,
independent observer identity, expectation start, configuration/rule revision,
heartbeat interval, grace and observer freshness budgets. Expectations must be
authorized before silence. A trusted adapter authenticates each independent probe;
constructing or deserializing an observation supplies no authentication authority.
No incoming telemetry or self-reported healthy flag can replace that adapter.

A healthy, current observer with a verified heartbeat produces NoMatch until the
heartbeat interval plus grace expires. Once overdue, it produces Match for a
collection gap, without attributing compromise or cause. If no heartbeat has ever
been verified, the expectation start supplies the deadline. Missing or unknown
expected inventory refuses configuration; the host must expose unavailable,
indeterminate coverage. Missing/stale/unhealthy observer evidence or a required
missing checkpoint yields Indeterminate. Silence from an unobservable collector
is never healthy silence.

Source/binding/observer/revision, observation sequence/time, heartbeat and checkpoint
are pinned. Changed identity reuse, regressions and future timestamps are refused.
Exact replay does not refresh either heartbeat or observer verification. A fresh
independent observation of the same old heartbeat may refresh observer health,
but cannot postpone its source deadline. Evaluation clocks cannot move backwards,
including after restoring a snapshot. Expiry is checked at evaluation time.

Inventory and state bytes are finite. Each expected source retains at most one
observation plus its last verified heartbeat/checkpoint. One evaluation returns at
most one assessment per source. The pure stage owns no worker, queue or scheduler;
the embedding host must bound cadence, operations, retained outputs and I/O.
Versioned snapshots bind the exact policy/inventory and validate all retained
observations before restoration. Persisted snapshots alone are not independently
current evidence.

Completion still requires the authenticated independent-observer adapter, native
Main lifecycle, persisted original assessment/finding outbox and checkpoint in one
transaction, replay/lost-reply/crash recovery, bounded history/retention/metrics,
focused source review and applicable frozen workspace/process/native gates. A
counter or pure evaluator alone cannot close SENSOR-HEALTH. Production observer
independence remains an explicit environment qualification boundary.

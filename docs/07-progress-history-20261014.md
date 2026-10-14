# Earlier CI and recovery evidence

Moved unchanged from the current progress page on2026-10-14. Statements below
retain their original revision, date and evidence boundaries.

The completed`8f14fb0` run38146772722 passes AMD64 Rust and MCP, but ARM64 fails
only the cancellation helper's readiness-stage assertion; container/Kubernetes
jobs are skipped. Its GitHub-digest-verified public artifact and exact local
reproduction are retained under`target/arm64-native-helper-20261012/`.

Writer-reviewed`71e45a9` fixes the test-only startup interval while preserving
strict readiness, injected-delay witness and physical child-reaping assertions.
All22native helper/16CI-wrapper tests and14workspace boundaries pass. Production
deadlines and Rust/build inputs are unchanged. The subsequent`bee52db`
run38206257117 completed successfully; its retained ARM64 qualification verifies
the earlier Small/default runtime scope, not the current Standard deployment.

Pushed`6fdc163` adds exact all-feature Standard prebuild and bounded pipeline/
stopped-lifecycle qualification to both native Rust jobs, with existing pinned
PostgreSQL and always-retained diagnostics. Workflow lint,36guards and14workspace
boundaries pass. Run38212500862 at`16ca254` now passes both native Rust jobs.
GitHub-digest-verified artifacts bind five Standard executable scenarios per
architecture, native ELF/binary identities,159current runtime source hashes and
owned container cleanup. Runtime totals are170.97s AMD64 and168.97s ARM64.
Real PostgreSQL TLS and simulated versioned S3 qualify this process scope;
Standard Kubernetes, private consumer/restore and AWS remain separate gates.
Evidence: `target/native-ci-monitor-20261012/VERIFIED-NATIVE-STANDARD.json`.
Both container/Kubernetes jobs were still building production images at the
retained observation. Full current-revision remote acceptance remains open.

## Agent recovery oracle correction — 2026-10-12

The Standard-enabled`f299633` run38208362422 fails ARM64 at
`signal-agent --test process` after saturated-spool SIGKILL/restart. Its original
log lacks actual row/ID counts. A real lost-admission reply reproduces the same
failure with20stored rows,12original IDs and no missing events: ADR012 permits
at-least-once delivery, while the old oracle incorrectly required one physical row.

Writer-reviewed`7d5d83f` verifies complete logical delivery and immutable full
payload per ID. It captures8synced CRC-framed originals beforeSIGKILL, verifies
their exact restarted transmission, drops a real fully accepted HTTP reply,
requires exact replay, and retains all12originals plus an appended13th through
server restart. Different IDs for repeated lines, payload changes and missing
originals still fail. Five guard tests, the real process run, both Cargo process
tests, workflow lint and14workspace boundaries pass. No production behavior or
deadline changes. Evidence: `target/arm64-agent-process-20261012/ACCEPTANCE.json`.
Both native Rust jobs now pass at`16ca254`; complete container/Kubernetes and
latest-revision CI still require their own matching evidence.

## Standard Helm runtime configuration prepared — 2026-10-12

Writer-reviewed`0addc76` selects external runtime config-file and environment
Secrets through bounded explicit references. Four supported config selectors mount
as read-only regular subPath files; selected Standard cache stays on the PVC.
Default deployment is byte-identical. Default/selected Helm lint,12rejected unsafe
cases, manifest checks, five cluster-helper guards and14workspace boundaries pass.
Evidence: `target/helm-runtime-config-20261012/`. This render proof alone did not
close actual Standard startup/recovery/cleanup or independent full-item review;
their later local acceptance is recorded below. EKS/release gates remain open.


## Earlier incremental STANDARD-RECOVERY records

STANDARD-RECOVERY is in progress — 2026-10-14. A37.90s owned actual Standard
server-loss guard removes local WAL/cache after checked producer-copy release.
The exact independently retained object is reconstructed, but replacement
correctly refuses its missing enrolled WAL identity and drains. The recovered
original stays retained. Evidence:`target/standard-recovery-20261014/ACCEPTANCE.json`.
Follow-up:`target/standard-checkpoint-recovery-20261014/ACCEPTANCE.json` passes
75.16s. Exact independently retained stopped-WAL bytes restore replacement in
17.47s including lease expiry; corrupt backup refuses, same original receipt
gets fresh custody. RPO0 covers only the4byte fixture with control/object domains
surviving. Next:consistent control-domain backup/restore, stale owners and explicit
production restore authority; general failover/RPO/RTO remain unqualified.

Custody-only restore roots now pass7frozen gates:933default/994all-feature
tests, both strict Clippy modes and18-case PostgreSQL matrix121.29s. Missing
custody inventory or original bytes refuses restore; original receipt bytes
remain unchanged. Evidence:`target/restore-custody-roots-20261014/ACCEPTANCE.json`.
The existing-only lineage resolver now passes7frozen gates and PostgreSQL
matrix137.01s. Explicit owner installation, sealed restored lineage/current
owner, exact historical bytes, missing-record/conflict/seal/routine refusal and
unchanged quota are exercised. Metadata remains separate from a release permit.
Evidence:`target/restored-custody-lineage-20261014/ACCEPTANCE.json`.
Fresh restored confirmation now passes7gates935default/996all-feature and
PostgreSQL matrix124.66s: three existing-only lineage checks bracket two current
retained reads; original description/digest and receipt/quota stay exact, and
cancellation/missing originals refuse. Evidence:
`target/restored-custody-confirmation-20261014/ACCEPTANCE.json`.
Selected startup credentials now pass10gates, PostgreSQL143.37s and native
restored Standard77.36s: exact readonly metadata/resolve grants, artifact/owner
checks, ordinary-profile refusal and normal resume after test-only revocation.
Evidence:`target/restored-custody-startup-20261014/ACCEPTANCE.json`.
Next:configured native authenticated API/SDK restored reconfirmation.


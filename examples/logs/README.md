# Synthetic vendor log corpus

This public corpus contains **55 original synthetic records: five cases from each
of 11 source families**, paired with canonical SIGNAL schema-v1 events. It is
shared test data for the public project and separately versioned private overlays.
Account `000000000001`, documentation IP ranges, invented UUIDs/device identities
and `example.invalid` names are fixtures. No customer exports or credentials are
included. Example timestamps describe scenarios; they do not date validation.

Each source JSON contains `raw` (including its trailing newline), `raw_sha256`,
`raw_format`, `native_severity`, `expected` and an illustrative `security` assessment.
`manifest.json` binds source files and aggregate files by SHA-256 and pins the
corpus to the workspace development version. `canonical.ndjson` contains one
normalized reference event per line; `ingest-batch.json` is an HTTP batch body.
These expected events are authored reference mappings. Vendor adapters, live
collection, correlation and source coverage are separate implementation work.

## Sources and formats

| File | Selected format | Example scenarios | Primary format reference |
| --- | --- | --- | --- |
| [aws-cloudtrail.json](aws-cloudtrail.json) | Individual management-event record, eventVersion 1.11 | Inventory, denied decrypt, public SSH ingress, access key creation, stopped logging | [CloudTrail fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) |
| [aws-cloudwatch.json](aws-cloudwatch.json) | Decoded subscription `DATA_MESSAGE`, millisecond event time; application JSON inside `message` | Debug health, successful/failed login, authorization denial, sensitive export | [Subscription envelope](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html) |
| [aws-rds.json](aws-rds.json) | PostgreSQL text with an explicitly configured timestamp/pid/user/database/app/client prefix | Query plan, connection, failed password, rds_superuser grant statement, WAL storage panic | [RDS PostgreSQL logging](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.Concepts.PostgreSQL.html) |
| [aws-alb.json](aws-alb.json) | HTTPS access log, 33 fields through `transform_status` | Health, missing route, WAF block, backend error, admin export request | [ALB access logs](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html) |
| [aws-nlb.json](aws-nlb.json) | TLS connection access log, v2.0, 22 fields | Connection, bad certificate alert, large transfer, legacy TLS, internal TLS alert | [NLB access logs](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-access-logs.html) |
| [aws-eks.json](aws-eks.json) | `audit.k8s.io/v1` Event, `ResponseComplete`, Metadata or Request level | Pod listing, secret access, denied exec, privileged pod, cluster-admin binding | [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/), [EKS control-plane logging](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html) |
| [aws-ecs.json](aws-ecs.json) | EventBridge task lifecycle; application stdout JSON; CloudTrail configuration event | Running/failed task, failed login, sensitive export, privileged EC2 task definition | [ECS state events](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_task_events.html), CloudTrail reference above |
| [cloudflare.json](cloudflare.json) | Logpush `firewall_events` with RFC3339 timestamp output selected | Allow, managed challenge, WAF block, rate limit, monitor-only rule | [Firewall dataset](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/firewall_events/) |
| [office365.json](office365.json) | Management Activity API STS and Exchange-admin records | Successful/failed login, conditional access block, mailbox forwarding, disabled audit ingestion | [Microsoft 365 audit schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema) |
| [cato-vpn.json](cato-vpn.json) | Selected EventsFeed `EventRecord { time, fieldsMap }` projection | VPN connection/disconnection/auth failure, Internet firewall block, IPS block | [EventRecord shape](https://knowledge.catonetworks.com/v1/docs/cato-api-eventsfeed-eventrecord-large-scale-event-monitoring), [Cato schema explorer](https://knowledge.catonetworks.com/docs/cato-event-schema) |
| [fortigate.json](fortigate.json) | FortiOS 7.4 key/value SSL VPN event and forward traffic | VPN tunnel up, three login-failure contexts, closed HTTPS session | [VPN login failure](https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference/39426/39426-log-id-event-ssl-vpn-user-ssl-login-fail), [VPN success example](https://community.fortinet.com/t5/FortiGate/Technical-Tip-SSL-VPN-event-logs-when-successfully-connected/ta-p/331206) |

CloudWatch's fixture is the decoded payload; its actual subscription transport
uses base64/gzip. RDS and ECS application messages depend on configured logging
and instrumentation. The PostgreSQL grant uses the RDS `rds_superuser` role;
a statement log alone does not prove completion, so its outcome is `unknown`.
EKS pod/RBAC specifications require Request-level audit
records; Metadata records do not supply them. NLB records contain TLS connection
fields, without HTTP paths/statuses. Their best-effort delivery does not establish
complete security coverage. A large byte count or successful admin URL alone is
a candidate for investigation, not proof of data exfiltration.

Cato's documented API projection is represented, but selected subtype/message/
action values remain illustrative until a tenant's current schema/enum export is
reviewed. The manifest records this limitation. No Cato adapter qualification is
claimed. Extra vendor fields and version-specific variations need further fixtures.

## Severity and policy

`expected.severity` is **log severity**, from `debug` through `critical` in this
corpus. `security.severity` is an illustrative **finding severity**:
`none`, `low`, `medium`, `high`, `critical`. It is fixture metadata, outside the
event; the rule engine does not turn it into findings. CloudTrail audit records
remain log `info` even when stopping audit collection warrants a critical
investigation. A PostgreSQL PANIC is log critical and may be an operational
failure. FortiOS `alert` maps to log critical while a single failed VPN login can
have low security severity. Company thresholds, approved changes, asset
criticality, suppression, correlation and SecOps routing stay in the private repo.

STS login failure examples deliberately retain a successful HTTP `ResultStatus`.
Their `Operation`, `ErrorCode` and `LogonError` still indicate failed authentication;
[Microsoft documents this distinction](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#common-schema).
Raw evidence stays under `attributes.log.original`; actors/identity, object details
and unselected vendor fields can be read there rather than discarded.

## Local use

```bash
python3 scripts/check-log-samples.py --self-test
```

The checker verifies all 11 families, positive/negative scenarios, raw byte hashes,
aggregate equality, selected native envelopes, time/outcome/severity mappings and
seven rejection cases. It checks fixtures, not arbitrary vendor input. The private
`tests/vendor_samples.rs` consumes these same files, deserializes and validates all
55 events using the real Rust event contract, applies private enrichment and
checks private rule outcomes. That proof uses sibling source dependencies.

For a disposable local server with its own data root and configured token:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${SIGNAL_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data-binary @examples/logs/ingest-batch.json \
  http://127.0.0.1:8080/v1/events/batch
```

The batch body is approximately 84 KiB and must fit the server's configured
request and queue limits. Replay into a reused environment may duplicate event
IDs because independent HTTP admissions are at least once. No vendor endpoint
or cloud credential is needed for these examples.

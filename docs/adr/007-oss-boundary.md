# ADR-007: OSS mechanism and private policy boundary

Status: Established by the supplied architecture specification.

## Context and decision

The public project must remain reusable. Account inventories, roles, buckets,
ownership metadata, private detections and deployment values belong in a separate
private overlay. It depends on Signal; Signal never depends on it.

Use nested JSON attributes and generic SDK interfaces for extension. Add only the
smallest generic hook when the overlay proves one is missing. Existing overlay
design documentation illustrates this contract; it is not runtime policy.

## Consequences and verification

No company namespace or identifiers may enter Rust runtime code, public sample
rules or deployment configuration. Phase reviews inspect this boundary and Phase
7 proves extension without copying or forking OSS source.

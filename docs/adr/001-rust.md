# ADR-001: Rust

Status: Established by the supplied architecture specification.

## Context and decision

Signal needs bounded resource use and equal Linux AMD64/ARM64 support. Use stable
Rust in a Cargo workspace, with Tokio and Axum introduced in Phase 1. Phase 0 uses
only the standard library and local crate dependencies.

## Consequences and verification

Pin Rust 1.94.1, edition 2024, with a 1.94 minimum. Require formatting, Clippy and
workspace tests. Keep dependencies centralized and add them only when used.
The foundation gates and CI architecture matrix verify this decision.

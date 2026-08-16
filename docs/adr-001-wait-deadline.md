# ADR 001 — Wait mode requires an explicit deadline

## Status: accepted

## Context

Health-gate wait loops (`until service is up`) are the single most common failure
mode in CI: an unbounded loop hangs the pipeline when the service never comes up.

## Decision

`--wait` is only permitted together with `--deadline > 0`. Without a deadline the
CLI exits with code 2 (invalid input). The default configuration (no `--wait`)
performs exactly one probe per target and exits immediately.

## Consequences

- CI pipelines can always compute a worst-case duration statically.
- Users who want long waits must acknowledge the bound explicitly.
- The engine still enforces the deadline internally even if the clock runs fast.

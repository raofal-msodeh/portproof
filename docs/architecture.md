# PortProof — Architecture

## Layering

```
cli.py          Argument parsing, input validation, exit-code mapping, report writing
models.py       Pure data: Target, ProbeConfig, ProbeResult, Report + validation
engine.py       Probe execution with injectable ClockSockets IO bundle
errors.py       Exit-code-aligned exception hierarchy
```

## Determinism by injection

Every wall-clock read and socket connect flows through the `ClockSockets` dataclass
(`time`, `sleep`, `connect_tcp`, `connect_tls`, `connect_tls_ca`, `http_probe`).
Production uses `_RealClockSockets` (stdlib); tests substitute `FakeClockSockets`,
which advances a monotonic clock on each `time()` call and simulates open/closed/
refused/handshake-failed outcomes without touching the network. This lets the full
engine — including wait loops, deadlines, and attempt limits — be exercised in
milliseconds.

## Status taxonomy

| Status | Evidence |
|---|---|
| `open` | connection established (TCP/TLS) or 2xx/3xx HEAD (HTTP) |
| `closed` | connection refused (service down) |
| `filtered` | connection timed out (firewall / overload) |
| `error` | protocol-level failure (TLS handshake collapse, HTTP 4xx/5xx, malformed response) |

## Exit-code contract

`0` pass · `1` probe failure · `2` invalid input · `3` internal error.
Wait mode requires an explicit `--deadline`, so no configuration can hang forever.

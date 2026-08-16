# PortProof

> Deterministic port and service verification with auditable JSON evidence.

**portproof** verifies that local or remote TCP, TLS, and HTTP endpoints accept connections, and records cryptographically clean machine-readable evidence of every probe. It is designed for CI pipelines, deployment health-gates, and runbook automation where "the port looked open but did the service actually respond?" is a question you must answer *for the record*.

Unlike ad-hoc `nc -z` one-liners, PortProof exits with well-defined codes, writes a signed-by-design JSON report (timestamps, per-target status, elapsed probe latency, TLS handshake state, HTTP status), supports a deadline-driven wait mode that blocks until a service becomes ready, and accepts fully injectable IO so every behavior is reproducible in tests.

## Features

- **Three probe protocols**: `tcp` (connection only), `tls` (full TLS handshake), and `http` (HEAD request with status-code gate).
- **Structured evidence**: every run can write a `report.json` containing per-target status, reason, elapsed milliseconds, and — for HTTP probes — the exact status code and scheme observed.
- **Wait mode**: `--wait --deadline N --interval I` loops until the first target opens, bounded by a hard total deadline (so CI jobs cannot hang forever).
- **Predictable exit codes**: `0` = verification passed, `1` = one or more targets failed, `2` = invalid input, `3` = internal engine failure.
- **Deterministic core**: all time and socket access flows through an injectable `ClockSockets` bundle, enabling 100 ms test suites with zero network dependencies for business logic.
- **Zero runtime dependencies**: the standard library only; installs in seconds, ships in containers trivially.
- **Fail modes**: `--fail-mode all` (default: every target must be open) or `--fail-mode any` (succeed if at least one target is open).

## Quick start

```bash
pip install .                       # or: pip install -e .[dev]
portproof localhost:8080            # TCP check, exit 0 when open
portproof api.example.com:443 -p tls            # TLS handshake check
portproof localhost:9000 -p http --http-path /health   # HTTP 2xx/3xx gate
portproof db:5432 cache:6379        # batch: both must be open (exit 0)
```

### Wait for a service to be ready

```bash
# Block until the database accepts TLS connections, at most 60 s.
portproof db:5432 -p tls --wait --deadline 60 --interval 1
```

### Record evidence

```bash
portproof api:443 -p tls --report proof.json --format json
```

`proof.json` then contains:

```json
{
  "passed": true,
  "fail_mode": "all",
  "deadline_iso": "2026-08-16T12:00:00+00:00",
  "targets": [
    {
      "target": "api:443",
      "protocol": "tls",
      "status": "open",
      "reason": "tls handshake completed",
      "elapsed_ms": 41.2
    }
  ]
}
```

## Target syntax

Targets are written as `host:port`. Bracketed IPv6 is supported (`[::1]:443`), and duplicate targets are deduplicated automatically. Hosts must be plain ASCII; fractional ports, bare ambiguous IPv6, and injection-style characters are rejected with exit code 2.

| Example | Meaning |
|---|---|
| `localhost:8080` | IPv4/hostname on port 8080 |
| `[::1]:443` | IPv6 loopback, bracketed |
| `db.internal:5432` | FQDN |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Verification passed (per `--fail-mode`) |
| `1` | One or more targets failed (`closed` / `filtered` / `error`) |
| `2` | Invalid input (target syntax, negative timeout, `--wait` without `--deadline`) |
| `3` | Internal engine error (should not happen) |

### Probe outcomes

Each target resolves to one of four statuses: `open` (proof obtained), `closed` (connection refused — the service is down), `filtered` (connection timed out — firewall or overloaded), and `error` (protocol-level failure such as a TLS handshake collapse or an HTTP 5xx).

## Reference

```
usage: portproof [-h] [-p {tcp,tls,http}] [-t TIMEOUT] [-d DEADLINE]
                 [--wait] [--interval INTERVAL] [--attempts ATTEMPTS]
                 [--fail-mode {all,any}] [--format {json,text}]
                 [--report REPORT] [--quiet] [--tls-ca TLS_CA]
                 [--http-path HTTP_PATH] [--version]
                 targets [targets ...]

Verify that ports and services accept connections.

positional arguments:
  targets               host:port targets (e.g. localhost:8080, [::1]:443)

options:
  -p, --protocol        probe protocol: tcp (default), tls, http
  -t, --timeout         per-target connection timeout in seconds (default 5)
  -d, --deadline        total run deadline in seconds; required with --wait
  --wait                loop until a target opens or the deadline elapses
  --interval            seconds between wait-loop attempts (default 1)
  --attempts            max wait-loop attempts; 0 = unlimited within deadline
  --fail-mode           exit-0 condition: all (default) or any
  --format              output format: text (default) or json
  --report              write JSON evidence report to this file
  --quiet               suppress text output
  --tls-ca              PEM CA bundle used to trust the TLS certificate chain
  --http-path           HTTP probe path (default "/")
```

## As a library

```python
from portproof.engine import verify_target
from portproof.models import ProbeConfig, Protocol, Target

result = verify_target(
    Target("localhost", 8080),
    ProbeConfig(timeout=2.0, protocol=Protocol.TCP),
)
print(result.status, result.elapsed_ms)   # PortStatus.OPEN  12.4
```

Inject `FakeClockSockets` (see `tests/test_engine.py`) to unit-test anything that depends on probing without touching the network.

## Why not `nc -z` or `wait-for-it`?

Shell one-liners produce no structured evidence, conflate connection errors with firewalls, and — in the case of busy-wait loops — hang CI pipelines indefinitely when a deadline is not enforced. PortProof separates **proof** (open/filtered/closed/error with reason and latency), **auditability** (deterministic JSON report with ISO timestamps), and **safety** (hard deadlines, explicit exit codes, and input validation).

## Development

```bash
make setup   # install dev deps
make qa      # ruff + mypy + pytest + build
make test    # pytest only
make rt      # red-team adversarial scenarios (20 cases)
```

The engine is fully testable via IO injection: every probe goes through `ClockSockets`, and `tests/test_engine.py` drives it with `FakeClockSockets` — so business-logic tests never open a real socket.

## Quality

| Gate | Result |
|---|---|
| `ruff check --select ALL` | clean |
| `mypy --strict` | no issues |
| `pytest` | 70 tests passing |
| `scripts/red_team.sh` | 20 adversarial scenarios passing |
| Runtime dependencies | 0 |

## License

MIT — see [LICENSE](LICENSE).

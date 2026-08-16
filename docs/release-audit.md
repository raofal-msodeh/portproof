# Release audit — 1.0.0

| Gate | Tool | Result |
|---|---|---|
| Lint | ruff check --select ALL (src + tests) | 0 findings |
| Format | ruff format --check | clean |
| Types | mypy --strict (src) | no issues |
| Tests | pytest (70 tests) | 70 passed, 0 failed |
| Red-team | scripts/red_team.sh (20 scenarios) | 20 passed, 0 failed |
| Build | python3 -m build (sdist + wheel) | OK |

### Threat-model outcomes

- Host/protocol injection via crafted `host:port` specs: rejected at validation (exit 2).
- Unicode / oversized specs: rejected (isascii, length cap).
- Fractional or out-of-range ports: rejected.
- Bare ambiguous IPv6: rejected; bracketed IPv6 accepted.
- Unbounded wait loops: impossible by design (--wait requires --deadline).
- Negative timeouts / intervals: rejected.
- TLS against non-TLS services: reported as `error`, never `open`.
- Plain-text HTTP credentials never exchanged (HEAD probe only).
- Report path traversal: report is written only to the caller-supplied path; no
  template-driven file composition.

### Dependency posture

Zero runtime dependencies (Python stdlib only). Dev dependencies: pytest, ruff,
mypy, build.

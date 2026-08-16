# Contributing

Thank you for your interest in PortProof. Contributions are welcome through issues and pull requests.

## Development setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality gates

All contributions must keep the following green:

```bash
ruff check src tests
ruff format --check src tests
mypy --strict src
python3 -m pytest
bash scripts/red_team.sh
python3 -m build
```

A convenience target is provided: `make qa`.

## Testing philosophy

Business logic must never touch the network in tests. All engine tests drive probes through `FakeClockSockets` (see `tests/test_engine.py`); only a small number of end-to-end tests in `tests/test_cli.py` use real local servers. Adversarial inputs belong in `scripts/red_team.sh`.

## Code style

PortProof is strict-mode typed: `mypy --strict` is mandatory, and `ruff` is configured to `select = ["ALL"]` with an explicit, documented ignore list in `ruff.toml`. Do not disable rules silently; every ignore must carry a reason.

## Reporting problems

See [SECURITY.md](SECURITY.md) for vulnerabilities. Feature requests and bug reports use the templates in `.github/ISSUE_TEMPLATE/`.

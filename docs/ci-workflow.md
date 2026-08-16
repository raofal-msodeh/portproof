# CI workflow (suggested)

```yaml
name: CI
on: [push, pull_request]
jobs:
  qa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.11"}
      - run: pip install -e ".[dev]"
      - run: make qa
```

Run `make qa` in CI: lint, format check, strict type check, tests, red-team, and
a verified build in a single command.

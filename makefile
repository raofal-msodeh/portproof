.PHONY: setup qa test rt build fmt lint typecheck clean

setup:
	pip install -e ".[dev]"

qa: fmt lint typecheck test rt build
	@echo "all quality gates passed"

lint:
	ruff check src tests

fmt:
	ruff format --check src tests

typecheck:
	mypy --strict src

test:
	python3 -m pytest

rt:
	bash scripts/red_team.sh

build:
	python3 -m build

clean:
	rm -rf dist build src/*.egg-info .mypy_cache .ruff_cache .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

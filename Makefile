.PHONY: test lint format typecheck check build clean distclean install install-tool install-dev

test:
	uv run pytest

lint:
	uv run ruff check
	uv run ruff format --check

format:
	uv run ruff format

typecheck:
	uv run ty check

check: lint typecheck test

build:
	uv build

install:
	uv pip install .

install-tool:
	uv tool install .

install-dev:
	uv sync

clean:
	rm -rf dist/ build/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache .ty

distclean: clean
	rm -rf .venv/

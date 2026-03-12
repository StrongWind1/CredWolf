.PHONY: test lint format typecheck check build clean distclean install install-tool install-dev docs docs-check docs-serve update-cli-ref

test:
	uv run pytest

lint:
	uv run ruff check
	uv run ruff format --check

format:
	uv run ruff format

typecheck:
	uv run ty check

check: lint typecheck test docs-check

build:
	uv build

install:
	uv pip install .

install-tool:
	uv tool install .

install-dev:
	uv sync

clean:
	rm -rf dist/ build/ *.egg-info site/
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache .ty .cache
	rm -rf htmlcov/ .coverage .coverage.* coverage.xml
	find . -type f -name "*.pyc" -o -name "*.pyo" | xargs rm -f

docs:
	uv run --group docs mkdocs build

docs-check: update-cli-ref docs
	uv run --group docs mkdocs build --strict
	uv run scripts/check-docs-links.py site
	@rm -rf site/
	@echo "Docs checks passed."

docs-serve:
	uv run --group docs mkdocs serve

update-cli-ref:
	uv run scripts/update-cli-reference.py

distclean: clean
	rm -rf .venv/

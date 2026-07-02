.PHONY: test lint format typecheck check build clean distclean install install-tool install-dev docs docs-check docs-serve hooks

test:
	uv run pytest

lint:
	uv run ruff check
	uv run ruff format --check

format:
	uv run ruff format
	uv run ruff check --fix

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

hooks:
	uv run pre-commit install

docs:
	uv run --group docs mkdocs build

docs-check:
	uv run --group docs mkdocs build --strict
	@rm -rf site/
	@echo "Docs checks passed."

docs-serve:
	uv run --group docs mkdocs serve

clean:
	rm -rf dist/ build/ site/ .cache/
	rm -rf .pytest_cache/ .ruff_cache/ .mypy_cache/ .ty/ .ty_cache/
	rm -rf htmlcov/ .coverage .coverage.* coverage.xml
	find . -path ./.venv -prune -o -type d -name '__pycache__' -exec rm -rf {} +
	find . -path ./.venv -prune -o -type d -name '*.egg-info' -exec rm -rf {} +
	find . -path ./.venv -prune -o -type f -name '*.py[co]' -exec rm -f {} +

distclean: clean
	rm -rf .venv/


# --- Release: bump version, refresh deps, verify, signed commit + signed tag, push ---
.PHONY: cut-release
cut-release:
	@test -n "$(VERSION)" || { echo "usage: make cut-release VERSION=X.Y.Z"; exit 1; }
	uv version "$(VERSION)"
	uv lock --upgrade
	$(MAKE) check
	git add pyproject.toml uv.lock
	@git diff --cached --quiet || git commit -S -m "chore(release): v$(VERSION)"
	git tag -s "v$(VERSION)" -m "v$(VERSION)"
	git push origin HEAD
	git push origin "v$(VERSION)"

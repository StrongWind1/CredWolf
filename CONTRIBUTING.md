# Contributing to CredWolf

## Getting started

```bash
git clone https://github.com/StrongWind1/CredWolf.git
cd CredWolf
uv sync          # install dependencies + dev tools
```

## Development workflow

```bash
make test        # run tests
make lint        # ruff check + ruff format check
make typecheck   # ty check
make check       # all of the above
```

Or without Make:

```bash
uv run pytest
uv run ruff check
uv run ruff format --check
uv run ty check
```

## Code style

- Python 3.11+ — use modern syntax (type unions with `|`, `match`, etc.)
- All code is linted with [Ruff](https://docs.astral.sh/ruff/) (`select = ["ALL"]` with targeted ignores)
- No docstrings required (disabled via `D` ignore) — write clear code and comments where needed
- Line length limit is 320 (effectively unlimited) — use judgement

## Submitting a pull request

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run `make check` and ensure everything passes
4. Open a PR against `main` with a clear description of what and why

## Reporting bugs

Use the [bug report template](https://github.com/StrongWind1/CredWolf/issues/new?template=bug_report.md). Include the exact command, full output with `-vvv`, and your environment details.

## Scope

CredWolf validates credentials and enumerates usernames. It does not perform post-authentication activity. Contributions that add post-auth features (share enumeration, command execution, data exfiltration, etc.) are outside scope and will not be accepted.

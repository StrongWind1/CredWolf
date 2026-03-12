FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /src
COPY . .

RUN uv sync --no-dev --frozen

ENTRYPOINT ["uv", "run", "credwolf"]

# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
# Dependencies first so source edits reuse this layer.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-install-project
COPY README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim
ARG GIT_SHA=""
LABEL org.opencontainers.image.source="https://github.com/BP602/ntfy-hermes-jev-bridge" \
      org.opencontainers.image.description="Local-first ntfy -> TypeSafe Jev -> Hermes notification gate"
RUN useradd --uid 10001 --user-group --home-dir /data --no-create-home bridge \
    && mkdir -p /data /config && chown bridge:bridge /data
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    NTFY_BRIDGE_CONFIG=/config/config.toml \
    BRIDGE_GIT_SHA=${GIT_SHA}
# Relative `bridge.database` paths land on the /data volume.
WORKDIR /data
VOLUME /data
USER bridge
EXPOSE 9464
# Requires `health.listen` on port 9464; /healthz answers 503 while ingestion or delivery is degraded.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9464/healthz', timeout=4)"]
ENTRYPOINT ["ntfy-bridge"]
CMD ["run"]

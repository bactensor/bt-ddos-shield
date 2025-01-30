ARG BASE_IMAGE=python:3.12-slim



FROM $BASE_IMAGE AS build-image
LABEL builder=true

COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /uvx /bin/

WORKDIR /root/src/
COPY pyproject.toml uv.lock ./

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1
# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

RUN --mount=type=cache,target=/root/.cache/uv \
	PDM_BUILD_SCM_VERSION=0 uv sync --frozen --no-install-project --no-dev --no-editable

COPY ./bt_ddos_shield /root/src/bt_ddos_shield
COPY ./docker/entrypoint.sh /root/src/

RUN --mount=type=cache,target=/root/.cache/uv \
	uv sync --frozen --no-dev --no-editable



FROM $BASE_IMAGE AS final-image
LABEL builder=false

WORKDIR /root/src/
ENV PYTHONUNBUFFERED=1
ENV PATH="/root/src/.venv/bin:$PATH"

ENV SQL_ALCHEMY_DB_URL=sqlite:///db/ddos_shield.db

COPY --from=build-image /root/src/ /root/src/



CMD ["./entrypoint.sh"]

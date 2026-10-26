# Admina Proxy — Python + Rust Hybrid Build
# Build context must be repo root (docker-compose handles this)
#
# Targets:
#   (default)  the proxy, nlp and telemetry extras, the Rust engine and the
#              bundled dashboard
#   slim       the proxy extra and the Rust engine, without the dashboard
#              files (docker build --target slim)
#
# Base images are pinned by digest; update each tag and digest together.
# uv and the Rust toolchain are used at build time only: neither is in the
# final images.

FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv
FROM rust:1.99-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS rust-toolchain

# Stage 1: Build Rust core. A failed build fails the image build.
FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8 AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential && \
    rm -rf /var/lib/apt/lists/*

# The toolchain of the official Rust image (same Debian release as the
# Python image), not the rustc of the Debian packages.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo

RUN --mount=from=uv,source=/uv,target=/bin/uv \
    uv pip install --system --no-cache maturin

WORKDIR /build
COPY core-rust/ ./core-rust/

RUN cd core-rust && maturin build --release

# Stage 2: application sources of the slim image (no dashboard files)
FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8 AS slim-sources

COPY admina/ /src/admina/
RUN rm -rf /src/admina/dashboard/static

# Stage 3: runtime base of both images
FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8 AS runtime

LABEL org.opencontainers.image.title="admina-proxy" \
      org.opencontainers.image.description="Admina governance proxy: MCP proxy and OpenAI-compatible gateway" \
      org.opencontainers.image.url="https://admina.org" \
      org.opencontainers.image.source="https://github.com/admina-org/admina" \
      org.opencontainers.image.documentation="https://github.com/admina-org/admina#readme" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.admina.engine="rust"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl && \
    rm -rf /var/lib/apt/lists/*

COPY LICENSE NOTICE /usr/share/licenses/admina/

# Deps come from the locked project manifest — single source of truth
COPY pyproject.toml uv.lock ./
# The interpreter of the base image, never a uv-managed download
# (.python-version, not copied, is the version of the development
# environment).
ENV UV_PYTHON_PREFERENCE="only-system" \
    UV_PYTHON_DOWNLOADS="never" \
    UV_NO_CACHE="1" \
    UV_COMPILE_BYTECODE="1"
ENV VIRTUAL_ENV="/app/.venv"
ENV PATH="/app/.venv/bin:$PATH"

COPY admina/proxy/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Run as a non-root, non-login system user. At runtime the proxy writes
# only to the directory of the filesystem forensic store
# (FORENSIC_BACKEND=filesystem) and to the file of the EU AI Act
# assessments (ADMINA_EU_AI_ACT_ASSESSMENTS_PATH). Each image creates
# /app/.admina/forensic and /app/.admina/compliance, the directories of the
# compose files, before /app/.admina is given to this user, so a volume mounted
# there starts owned by the same user.
RUN groupadd --system --gid 10001 admina && \
    useradd --system --uid 10001 --gid admina --no-create-home --shell /sbin/nologin admina

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uvicorn", "admina.proxy.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]

# Slim image: the proxy extra and the Rust engine, no dashboard files
FROM runtime AS slim

RUN --mount=from=uv,source=/uv,target=/bin/uv \
    --mount=from=rust-builder,source=/build/core-rust/target/wheels,target=/tmp/wheels \
    uv sync --frozen --no-dev --no-install-project --extra proxy && \
    uv pip install /tmp/wheels/*.whl

COPY --from=slim-sources /src/admina/ ./admina/
RUN python -m compileall -q /app/admina

# The application and its dependencies stay owned by root; the admina user
# owns only /app/.admina, where the proxy writes.
RUN mkdir -p /app/.admina/forensic /app/.admina/compliance && \
    chown -R admina:admina /app/.admina
USER admina

# Full image (default target)
FROM runtime AS full

RUN --mount=from=uv,source=/uv,target=/bin/uv \
    --mount=from=rust-builder,source=/build/core-rust/target/wheels,target=/tmp/wheels \
    uv sync --frozen --no-dev --no-install-project --extra proxy --extra nlp --extra telemetry && \
    uv pip install /tmp/wheels/*.whl

COPY admina/ ./admina/
RUN python -m compileall -q /app/admina

# The application and its dependencies stay owned by root; the admina user
# owns only /app/.admina, where the proxy writes.
RUN mkdir -p /app/.admina/forensic /app/.admina/compliance && \
    chown -R admina:admina /app/.admina
USER admina

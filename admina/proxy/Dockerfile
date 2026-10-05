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

# Stage 1: Build Rust core. A failed build fails the image build.
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential rustc cargo && \
    rm -rf /var/lib/apt/lists/*

# Install uv for fast Python package management
COPY --from=ghcr.io/astral-sh/uv:0.11.7@sha256:240fb85ab0f263ef12f492d8476aa3a2e4e1e333f7d67fbdd923d00a506a516a /uv /bin/uv

RUN uv pip install --system --no-cache maturin

WORKDIR /build
COPY core-rust/ ./core-rust/

RUN cd core-rust && maturin build --release

# Stage 2: application sources of the slim image (no dashboard files)
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e AS slim-sources

COPY admina/ /src/admina/
RUN rm -rf /src/admina/dashboard/static

# Stage 3: runtime base of both images
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e AS runtime

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

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.11.7@sha256:240fb85ab0f263ef12f492d8476aa3a2e4e1e333f7d67fbdd923d00a506a516a /uv /bin/uv

COPY LICENSE NOTICE /usr/share/licenses/admina/

# Deps come from the locked project manifest — single source of truth
COPY pyproject.toml uv.lock .python-version ./
ENV VIRTUAL_ENV="/app/.venv"
ENV PATH="/app/.venv/bin:$PATH"

COPY admina/proxy/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Run as a non-root, non-login system user. At runtime the proxy writes
# only to the directory of the filesystem forensic store
# (FORENSIC_BACKEND=filesystem). Each image creates /app/.admina/forensic,
# the FORENSIC_BASE_DIR of the compose files, before /app is given to this
# user, so a volume mounted there starts owned by the same user.
RUN groupadd --system --gid 10001 admina && \
    useradd --system --uid 10001 --gid admina --no-create-home --shell /sbin/nologin admina

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uvicorn", "admina.proxy.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]

# Slim image: the proxy extra and the Rust engine, no dashboard files
FROM runtime AS slim

RUN uv sync --frozen --no-dev --no-install-project --extra proxy

COPY --from=rust-builder /build/core-rust/target/wheels/ /tmp/wheels/
RUN uv pip install /tmp/wheels/*.whl && rm -rf /tmp/wheels

COPY --from=slim-sources /src/admina/ ./admina/

RUN mkdir -p /app/.admina/forensic && chown -R admina:admina /app
USER admina

# Full image (default target)
FROM runtime AS full

RUN uv sync --frozen --no-dev --no-install-project --extra proxy --extra nlp --extra telemetry

COPY --from=rust-builder /build/core-rust/target/wheels/ /tmp/wheels/
RUN uv pip install /tmp/wheels/*.whl && rm -rf /tmp/wheels

COPY admina/ ./admina/

RUN mkdir -p /app/.admina/forensic && chown -R admina:admina /app
USER admina

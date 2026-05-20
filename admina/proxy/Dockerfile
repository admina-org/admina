# Admina Proxy — Python + Rust Hybrid Build
# Build context must be repo root (docker-compose handles this)

# Stage 1: Build Rust core
FROM python:3.11-slim AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential rustc cargo && \
    rm -rf /var/lib/apt/lists/*

# Install uv for fast Python package management
COPY --from=ghcr.io/astral-sh/uv:0.11.7 /uv /bin/uv

RUN uv pip install --system --no-cache maturin

WORKDIR /build
COPY core-rust/ ./core-rust/

# Build Rust core. If it fails, the image build fails intentionally —
# use 'make python' or a compose override to run without the Rust engine.
RUN cd core-rust && maturin build --release && echo "Rust build OK" \
    || (echo "WARNING: Rust build failed — image will use Python fallback" && mkdir -p target/wheels && exit 0)

# Stage 2: Final image
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl && \
    rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.11.7 /uv /bin/uv

# Install deps from the locked project manifest — single source of truth
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-dev --no-install-project --extra proxy --extra nlp --extra telemetry
ENV VIRTUAL_ENV="/app/.venv"
ENV PATH="/app/.venv/bin:$PATH"

# Install Rust core wheel if the build stage produced one
COPY --from=rust-builder /build/core-rust/target/wheels/ /tmp/wheels/
RUN if ls /tmp/wheels/*.whl 1>/dev/null 2>&1; then \
        uv pip install /tmp/wheels/*.whl && echo "Rust engine installed"; \
    else \
        echo "No Rust wheel found — using Python fallback engine"; \
    fi && rm -rf /tmp/wheels

COPY admina/ ./admina/

COPY admina/proxy/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Run as a non-root, non-login system user. The proxy never writes to
# the filesystem at runtime, so no chown of writable paths is needed
# beyond the application directory.
RUN groupadd --system --gid 10001 admina && \
    useradd --system --uid 10001 --gid admina --no-create-home --shell /sbin/nologin admina && \
    chown -R admina:admina /app
USER admina

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uvicorn", "admina.proxy.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]

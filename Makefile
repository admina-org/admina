# ═══════════════════════════════════════════════════════════
#  Admina — Build System
# ═══════════════════════════════════════════════════════════

.PHONY: all rust python install test test-rust test-all bench clean docker docs

# Default: build everything
all: rust install

# Build Rust core engine
rust:
	@echo "Building Rust governance engines..."
	cd core-rust && maturin build --release
	@echo "Rust build complete"
	@ls -la core-rust/target/wheels/*.whl

# Install into current Python env
install: rust
	@echo "Installing admina-core..."
	uv pip install core-rust/target/wheels/*.whl --force-reinstall
	@echo "Installed"

# Install Python-only (no Rust)
python:
	@echo "Python-only mode (no Rust compilation needed)"
	uv sync --frozen --extra proxy --extra nlp --extra telemetry
	@echo "Python deps installed"

# Run full test suite (pytest)
# spaCy NER falls back to regex-only if en_core_web_sm is not installed
# (run 'make python' first for full spaCy support).
test:
	@echo "Running test suite..."
	uv run pytest tests/ -v --tb=short

# Run Rust unit tests
test-rust:
	@echo "Running Rust tests..."
	cd core-rust && cargo test && cargo clippy -- -D warnings

# Run all tests (Python + Rust)
test-all: test test-rust

# Run benchmark
bench:
	@echo "Running benchmark..."
	uv run python scripts/benchmark.py --quick

# Generate and build documentation
docs:
	@echo "Generating documentation..."
	uv run python scripts/generate_docs.py
	uv run mkdocs build
	@echo "Docs built in site/"

# Docker build (includes Rust compilation)
docker:
	docker compose build

# Clean build artifacts
clean:
	rm -rf core-rust/target
	rm -rf core-rust/*.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Clean"

# Generate secrets if needed
secrets:
	@./scripts/bootstrap-secrets.sh

# Quick start: build everything and launch
up: secrets
	docker compose up -d --build

# Show engine status
status:
	@cd proxy && uv run python -c "from engine_bridge import engine_status; import json; print(json.dumps(engine_status(), indent=2))"

help:
	@echo ""
	@echo "  Admina Build System"
	@echo "  ─────────────────────"
	@echo "  make all        — Build Rust + install (recommended)"
	@echo "  make rust       — Build Rust core only"
	@echo "  make python     — Python-only mode (no Rust needed)"
	@echo "  make install    — Install Rust wheel into Python"
	@echo "  make test       — Run Python test suite (pytest)"
	@echo "  make test-rust  — Run Rust tests (cargo test + clippy)"
	@echo "  make test-all   — Run all tests"
	@echo "  make bench      — Run benchmark suite"
	@echo "  make docker     — Docker build"
	@echo "  make secrets    — Generate secrets (.env) if needed"
	@echo "  make up         — Generate secrets + build + launch"
	@echo "  make status     — Show engine status (rust/python)"
	@echo "  make clean      — Remove build artifacts"
	@echo ""

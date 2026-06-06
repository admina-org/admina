# Contributing to Admina

Thank you for your interest in contributing to Admina! This project is maintained by
[Stefano Noferi](https://github.com/stefanoferi) and the open source community.

## Supported Platforms

| Platform | Versions | Status |
|----------|----------|--------|
| Linux (x86_64) | Ubuntu 20.04+, Debian 11+, Fedora 38+, RHEL 9+ | ✅ Tested in CI |
| macOS (Apple Silicon) | macOS 12 Monterey+ (arm64) | ✅ Tested in CI |
| macOS (Intel) | macOS 12 Monterey+ (x86_64) | ✅ Tested in CI |
| Windows | — | ❌ Not supported (Docker stack requires Linux containers) |

Python 3.11, 3.12 and 3.13 are tested in CI. The `.python-version` file pins 3.11
for reproducibility; [uv](https://docs.astral.sh/uv/) manages this automatically.

## Development Setup

### Prerequisites

- Python 3.11+ — managed automatically by uv via `.python-version`
- [uv](https://docs.astral.sh/uv/) — Python package manager (`curl -Ls https://astral.sh/uv/install.sh | sh`)
- Rust toolchain (stable) — required only if you modify `core-rust/` (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Docker + Docker Compose — for integration testing

#### Linux-specific dependencies

On **Debian / Ubuntu**:
```bash
sudo apt-get install -y build-essential python3.11-dev
```

On **Fedora / RHEL**:
```bash
sudo dnf install -y python3.11-devel gcc
```

These are needed only when building the Rust extension (`core-rust/`) locally.
CI and Docker do not require them.

#### macOS-specific notes

The Rust engine links against Python via the macOS Framework bundle.
The recommended workflow uses `cargo test --lib` (see below), which avoids this entirely.
If you need to run `cargo test` (full binary), see
[core-rust/.cargo/config.toml](core-rust/.cargo/config.toml) for Framework path configuration.

### Clone and Install

```bash
git clone https://github.com/admina-org/admina.git
cd admina

# Install all dependencies (runtime + dev tools) into a single venv
uv sync --group dev

# Verify the environment
uv run python -c "import admina; print('OK')"
```

### Run the Test Suite

```bash
# Full suite with coverage
.venv/bin/pytest tests/ -v --tb=short

# Quick run (no coverage report)
.venv/bin/pytest tests/ -q

# Single test file
.venv/bin/pytest tests/test_core/test_types.py -v
```

All tests must pass before submitting a PR. Do not skip or disable failing tests.

### Build the Rust Engine (optional)

The Rust engine lives in `core-rust/` and is a PyO3 extension module that accelerates
hot paths such as SHA-256 chain verification and cosine similarity. You only need to
rebuild it if you change the Rust source.

```bash
# One-time: install maturin
uv pip install maturin

# Build and install the extension into the active venv
VIRTUAL_ENV=.venv maturin develop --release --manifest-path core-rust/Cargo.toml

# Run Rust unit tests (pure Rust only, no Python linking required)
cd core-rust
PYO3_PYTHON=$(uv python find 3.11) cargo test --lib
cargo clippy -- -D warnings
```

### Linting and Formatting

```bash
# Lint
uv run ruff check .

# Auto-fix
uv run ruff check --fix .

# Format
uv run ruff format .
```

### Security Scans

```bash
# Source code scan
uv run bandit -r admina/ core/ sdk/ domains/ plugins/ cli/ proxy/ -ll -q

# Dependency vulnerability scan (advisory — does not block contribution)
uv run safety check --full-report
```

### Run the Full Stack Locally

```bash
# Copy example env and set your secrets
cp .env.example .env
# Edit .env: set CLICKHOUSE_PASSWORD, GRAFANA_ADMIN_PASSWORD

docker compose up --build

# Verify
curl http://localhost:8080/health
```

Services started:
| Port | Service |
|------|---------|
| 8080 | Governance proxy + Admin API |
| 3000 | Dashboard (Nginx + React) |
| 3001 | Grafana |
| 4317 | OpenTelemetry Collector (gRPC) |
| 8123 | ClickHouse HTTP |

---

## Architecture Overview

```
admina/                         # single top-level Python package
├── __init__.py                 # re-exports GovernedModel, GovernedData, GovernedAgent, ComplianceKit
├── sdk/                        # SDK primitives (Governed* classes)
├── core/                       # GovernanceRequest/Response, types, event bus, Rust bridge
├── domains/
│   ├── agent_security/         # injection firewall, loop breaker
│   ├── data_sovereignty/       # PII detection/redaction
│   ├── compliance/             # EU AI Act, NIS2, GDPR, OISG, forensic black box
│   └── ai_infra/               # LLM engine, RAG pipeline, Web UI
├── plugins/                    # 9 plugin base classes + registry + builtin/
├── proxy/                      # FastAPI governance proxy + dashboard static
├── cli/                        # admina CLI (init, dev, plugin, doctor, password)
├── dashboard/static/           # Alpine.js SPA bundled in the wheel
└── integrations/               # CrewAI / LangChain / n8n / OpenClaw / Cheshire Cat

core-rust/                      # PyO3 Rust extension (admina-core PyPI package)
dashboard/                      # nginx Dockerfile + static (Docker-stack path)
tests/                          # pytest suite mirroring admina/ structure
examples/                       # quickstart.py, crewai_governed.py, langchain_governed.py
```

**Key design invariant**: every governance feature works both via the SDK
(in-process) and the proxy (over the network). Functions in
`admina/domains/` are pure callables — they are protocol-agnostic and do
not know whether they are called from an SDK `await` or an HTTP request
forwarded by the proxy.

**Import conventions**:
- Everything is nested under `admina.*` — there are no other top-level
  packages on `sys.path` after `pip install admina-framework`.
- Inside the package, prefer absolute imports: `from admina.core.types import RiskLevel`
- Relative imports (`from .types import ...`) are accepted inside the same sub-package.

---

## How to Contribute

### Reporting Issues

- Use [GitHub Issues](https://github.com/admina-org/admina/issues) for bug reports and feature requests
- Include steps to reproduce, expected vs actual behavior, and your environment (OS, Python version, Docker version)

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes with clear, conventional commit messages (`feat(sdk):`, `fix(proxy):`, etc.)
4. Write tests for any new behaviour
5. Ensure all tests pass: `.venv/bin/pytest tests/ -v --tb=short`
6. Run linting: `uv run ruff check . && uv run ruff format --check .`
7. Add the Apache 2.0 license header to every new source file (see existing files for the format)
8. Open a Pull Request against `main`

### Commit Message Format

```
feat(sdk): add GovernedModel with Ollama adapter
fix(proxy): handle empty JSON-RPC params
refactor(domains): move PII engine to data-sovereignty domain
docs(contributing): add architecture overview
```

Scopes: `sdk`, `proxy`, `domains`, `plugins`, `dashboard`, `cli`, `docker`, `config`, `integrations`, `docs`, `ci`, `core`.

### Areas Where Help Is Welcome

See [ROADMAP.md](ROADMAP.md) for the planned direction from 0.9.x to 1.0
and beyond. In addition, the following areas accept contributions on an
ongoing basis regardless of the current milestone:

- New injection detection patterns (`admina/domains/agent_security/firewall.py`)
- PII patterns for additional jurisdictions (`admina/domains/data_sovereignty/`)
- New model adapters and data connectors as plugins
- New framework integrations (AutoGen, Haystack, LlamaIndex, etc.)
- Documentation, tutorials, and translated EU AI Act compliance guidance
- Performance benchmarks and Rust engine optimisations

---

## License

By contributing to Admina, you agree that your contributions will be licensed
under the Apache License 2.0, the same license as the project.

## Code of Conduct

Be respectful. Be constructive. We're building infrastructure that protects
people's data and safety — the community should reflect those values.

# Copyright © 2025–2026 Stefano Noferi & Admina contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Admina — Configuration loader.

Reads ``admina.yaml`` if present, falls back to ``.env`` variables for
backward compatibility.  Exposes a typed :class:`AdminaConfig` object.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("admina.config")

# PyYAML is an optional dependency — fall back gracefully.
try:
    import yaml  # type: ignore[import-untyped]

    _HAS_YAML = True
except ImportError:  # pragma: no cover
    _HAS_YAML = False


__all__ = ["AdminaConfig", "load_config"]

# ── Section dataclasses ──────────────────────────────────────


@dataclass
class PIIConfig:
    """PII redaction settings."""

    enabled: bool = True
    categories: list[str] = field(
        default_factory=lambda: [
            "email",
            "phone",
            "credit_card",
            "ssn",
            "iban",
            "ip",
            "person",
            "org",
        ],
    )
    ner_model: str = "en_core_web_sm"


@dataclass
class ResidencyConfig:
    """Data residency settings."""

    enabled: bool = True
    allowed_zones: list[str] = field(default_factory=lambda: ["local", "eu"])
    block_outbound: bool = True


@dataclass
class DataSovereigntyConfig:
    """Data-sovereignty domain."""

    enabled: bool = True
    pii: PIIConfig = field(default_factory=PIIConfig)
    residency: ResidencyConfig = field(default_factory=ResidencyConfig)
    classification_enabled: bool = True


@dataclass
class LLMConfig:
    """LLM backend settings."""

    enabled: bool = True
    backend: str = "ollama"
    model: str = "llama3.1:8b"
    gpu_autodetect: bool = True
    vram_limit_mb: int = 0


@dataclass
class RAGConfig:
    """RAG pipeline settings."""

    enabled: bool = True
    backend: str = "chromadb"
    chunk_size: int = 512
    chunk_overlap: int = 50
    embedding_backend: str = "ollama"
    embedding_model: str = "nomic-embed-text"


@dataclass
class WebUIConfig:
    """Web UI settings."""

    enabled: bool = True
    port: int = 3080
    auth_mode: str = "builtin"
    signup_enabled: bool = True


@dataclass
class AIInfraConfig:
    """AI-infra domain (opt-in)."""

    enabled: bool = False
    llm: LLMConfig = field(default_factory=LLMConfig)
    rag: RAGConfig = field(default_factory=RAGConfig)
    webui: WebUIConfig = field(default_factory=WebUIConfig)


@dataclass
class ProxyConfig:
    """Proxy settings."""

    port: int = 8080
    upstream: str = "http://localhost:9000"


@dataclass
class FirewallConfig:
    """Anti-injection firewall settings."""

    enabled: bool = True
    heuristic_threshold: float = 0.7


@dataclass
class LoopBreakerConfig:
    """Loop breaker settings."""

    enabled: bool = True
    window_size: int = 10
    similarity_threshold: float = 0.85
    max_consecutive: int = 3


@dataclass
class AgentSecurityConfig:
    """Agent-security domain."""

    enabled: bool = True
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    loop_breaker: LoopBreakerConfig = field(default_factory=LoopBreakerConfig)


@dataclass
class ForensicConfig:
    """Forensic black-box settings."""

    storage: str = "filesystem"
    bucket: str = "forensic-blackbox"


@dataclass
class OTELConfig:
    """OpenTelemetry settings."""

    endpoint: str = "http://localhost:4317"


@dataclass
class ComplianceConfig:
    """Compliance domain."""

    enabled: bool = True
    forensic: ForensicConfig = field(default_factory=ForensicConfig)
    eu_ai_act_enabled: bool = True
    otel: OTELConfig = field(default_factory=OTELConfig)


@dataclass
class DashboardConfig:
    """Dashboard settings."""

    enabled: bool = True
    port: int = 3000


@dataclass
class AlertChannelConfig:
    """A single alert channel."""

    type: str = "log"
    url: str = ""
    events: list[str] = field(default_factory=list)


@dataclass
class AdminaConfig:
    """Top-level Admina configuration.

    Constructed by :func:`load_config` — reads ``admina.yaml`` if present,
    otherwise falls back to ``.env`` variables.
    """

    version: str = "2.0"
    data_sovereignty: DataSovereigntyConfig = field(default_factory=DataSovereigntyConfig)
    ai_infra: AIInfraConfig = field(default_factory=AIInfraConfig)
    agent_security: AgentSecurityConfig = field(default_factory=AgentSecurityConfig)
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    forensic_store: str = "filesystem"
    auth_provider: str = "apikey"
    pii_engine: str = "spacy-regex"
    alert_channels: list[AlertChannelConfig] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    plugin_config: dict[str, Any] = field(default_factory=dict)

    # Storage — populated from .env fallback when YAML absent
    redis_url: str = "redis://localhost:6379/0"
    clickhouse_host: str = "localhost"
    clickhouse_port: int = 8123
    clickhouse_db: str = "admina"
    clickhouse_password: str = ""

    # Auth / rate-limit — populated from .env fallback
    admina_api_key: str = ""
    rate_limit_max_requests: int = 100
    rate_limit_window_seconds: int = 60
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:3000"


# ── YAML parsing helpers ─────────────────────────────────────


def _build_from_yaml(data: dict[str, Any]) -> AdminaConfig:
    """Build an :class:`AdminaConfig` from a parsed YAML dict."""
    domains = data.get("domains", {})

    # data_sovereignty
    ds_raw = domains.get("data_sovereignty", {})
    pii_raw = ds_raw.get("pii", {})
    res_raw = ds_raw.get("residency", {})
    ds = DataSovereigntyConfig(
        enabled=ds_raw.get("enabled", True),
        pii=PIIConfig(
            enabled=pii_raw.get("enabled", True),
            categories=pii_raw.get(
                "categories",
                [
                    "email",
                    "phone",
                    "credit_card",
                    "ssn",
                    "iban",
                    "ip",
                    "person",
                    "org",
                ],
            ),
            ner_model=pii_raw.get("ner_model", "en_core_web_sm"),
        ),
        residency=ResidencyConfig(
            enabled=res_raw.get("enabled", True),
            allowed_zones=res_raw.get("allowed_zones", ["local", "eu"]),
            block_outbound=res_raw.get("block_outbound", True),
        ),
        classification_enabled=ds_raw.get("classification", {}).get("enabled", True),
    )

    # ai_infra
    ai_raw = domains.get("ai_infra", {})
    llm_raw = ai_raw.get("llm", {})
    rag_raw = ai_raw.get("rag", {})
    ai = AIInfraConfig(
        enabled=ai_raw.get("enabled", False),
        llm=LLMConfig(
            enabled=llm_raw.get("enabled", True),
            backend=llm_raw.get("backend", "ollama"),
            model=llm_raw.get("model", "llama3.1:8b"),
            gpu_autodetect=llm_raw.get("gpu_autodetect", True),
            vram_limit_mb=llm_raw.get("vram_limit_mb", 0),
        ),
        rag=RAGConfig(
            enabled=rag_raw.get("enabled", True),
            backend=rag_raw.get("backend", "chromadb"),
            chunk_size=rag_raw.get("chunk_size", 512),
            chunk_overlap=rag_raw.get("chunk_overlap", 50),
            embedding_backend=rag_raw.get("embedding_backend", "ollama"),
            embedding_model=rag_raw.get("embedding_model", "nomic-embed-text"),
        ),
        webui=WebUIConfig(
            enabled=ai_raw.get("webui", {}).get("enabled", True),
            port=ai_raw.get("webui", {}).get("port", 3080),
            auth_mode=ai_raw.get("webui", {}).get("auth_mode", "builtin"),
            signup_enabled=ai_raw.get("webui", {}).get("signup_enabled", True),
        ),
    )

    # agent_security
    as_raw = domains.get("agent_security", {})
    px_raw = as_raw.get("proxy", {})
    fw_raw = as_raw.get("firewall", {})
    lb_raw = as_raw.get("loop_breaker", {})
    agent_sec = AgentSecurityConfig(
        enabled=as_raw.get("enabled", True),
        proxy=ProxyConfig(
            port=px_raw.get("port", 8080),
            upstream=px_raw.get("upstream", "http://localhost:9000"),
        ),
        firewall=FirewallConfig(
            enabled=fw_raw.get("enabled", True),
            heuristic_threshold=fw_raw.get("heuristic_threshold", 0.7),
        ),
        loop_breaker=LoopBreakerConfig(
            enabled=lb_raw.get("enabled", True),
            window_size=lb_raw.get("window_size", 10),
            similarity_threshold=lb_raw.get("similarity_threshold", 0.85),
            max_consecutive=lb_raw.get("max_consecutive", 3),
        ),
    )

    # compliance
    co_raw = domains.get("compliance", {})
    fo_raw = co_raw.get("forensic", {})
    ot_raw = co_raw.get("otel", {})
    comp = ComplianceConfig(
        enabled=co_raw.get("enabled", True),
        forensic=ForensicConfig(
            storage=fo_raw.get("storage", "filesystem"),
            bucket=fo_raw.get("bucket", "forensic-blackbox"),
        ),
        eu_ai_act_enabled=co_raw.get("eu_ai_act", {}).get("enabled", True),
        otel=OTELConfig(endpoint=ot_raw.get("endpoint", "http://localhost:4317")),
    )

    # dashboard
    dash_raw = data.get("dashboard", {})
    dash = DashboardConfig(
        enabled=dash_raw.get("enabled", True),
        port=dash_raw.get("port", 3000),
    )

    # alert channels
    alerts = [
        AlertChannelConfig(
            type=a.get("type", "log"),
            url=a.get("url", ""),
            events=a.get("events", []),
        )
        for a in data.get("alert_channels", [])
    ]

    return AdminaConfig(
        version=data.get("version", "2.0"),
        data_sovereignty=ds,
        ai_infra=ai,
        agent_security=agent_sec,
        compliance=comp,
        dashboard=dash,
        forensic_store=data.get("forensic_store", "filesystem"),
        auth_provider=data.get("auth_provider", "apikey"),
        pii_engine=data.get("pii_engine", "spacy-regex"),
        alert_channels=alerts,
        plugins=data.get("plugins", []),
        plugin_config=data.get("plugin_config", {}),
    )


def _build_from_env() -> AdminaConfig:
    """Build an :class:`AdminaConfig` from environment / ``.env`` variables.

    Maps the flat ``UPPERCASE`` env vars to the structured config object
    so the rest of the codebase can use a single interface.
    """

    def _env(key: str, default: str = "") -> str:
        return os.environ.get(key, default)

    def _env_int(key: str, default: int) -> int:
        raw = os.environ.get(key)
        if raw is None:
            return default
        try:
            return int(raw)
        except ValueError:
            return default

    def _env_float(key: str, default: float) -> float:
        raw = os.environ.get(key)
        if raw is None:
            return default
        try:
            return float(raw)
        except ValueError:
            return default

    def _env_bool(key: str, default: bool) -> bool:
        raw = os.environ.get(key)
        if raw is None:
            return default
        return raw.lower() in ("1", "true", "yes")

    return AdminaConfig(
        agent_security=AgentSecurityConfig(
            proxy=ProxyConfig(
                upstream=_env("UPSTREAM_MCP_URL", "http://localhost:9000"),
            ),
            firewall=FirewallConfig(
                enabled=_env_bool("INJECTION_FAST_PATH_ENABLED", True),
            ),
            loop_breaker=LoopBreakerConfig(
                window_size=_env_int("LOOP_WINDOW_SIZE", 10),
                similarity_threshold=_env_float("LOOP_SIMILARITY_THRESHOLD", 0.85),
                max_consecutive=_env_int("LOOP_MAX_CONSECUTIVE", 3),
            ),
        ),
        compliance=ComplianceConfig(
            otel=OTELConfig(endpoint=_env("OTEL_ENDPOINT", "http://localhost:4317")),
            forensic=ForensicConfig(
                bucket=_env("FORENSIC_S3_BUCKET", "forensic-blackbox"),
            ),
        ),
        redis_url=_env("REDIS_URL", "redis://localhost:6379/0"),
        clickhouse_host=_env("CLICKHOUSE_HOST", "localhost"),
        clickhouse_port=_env_int("CLICKHOUSE_PORT", 8123),
        clickhouse_db=_env("CLICKHOUSE_DB", "admina"),
        clickhouse_password=_env("CLICKHOUSE_PASSWORD", ""),
        admina_api_key=_env("ADMINA_API_KEY", ""),
        rate_limit_max_requests=_env_int("RATE_LIMIT_MAX_REQUESTS", 100),
        rate_limit_window_seconds=_env_int("RATE_LIMIT_WINDOW_SECONDS", 60),
        log_level=_env("LOG_LEVEL", "INFO"),
        cors_origins=_env("CORS_ORIGINS", "http://localhost:3000"),
    )


# ── Public API ───────────────────────────────────────────────


def load_config(
    yaml_path: str | Path | None = None,
    *,
    search_paths: list[str | Path] | None = None,
) -> AdminaConfig:
    """Load configuration from ``admina.yaml`` or ``.env`` fallback.

    Args:
        yaml_path: Explicit path to a YAML config file.
        search_paths: Directories to search for ``admina.yaml`` when
            *yaml_path* is not given.  Defaults to cwd and repo root.

    Returns:
        A fully populated :class:`AdminaConfig` instance.
    """
    # 1. Explicit path
    if yaml_path is not None:
        path = Path(yaml_path)
        if path.is_file() and _HAS_YAML:
            return _load_yaml(path)

    # 2. Search common locations
    if search_paths is None:
        search_paths = [Path.cwd(), Path(__file__).resolve().parent.parent]
    for base in search_paths:
        candidate = Path(base) / "admina.yaml"
        if candidate.is_file() and _HAS_YAML:
            return _load_yaml(candidate)

    # 3. Fallback to environment / .env
    logger.info("No admina.yaml found — using .env fallback")
    return _build_from_env()


def _load_yaml(path: Path) -> AdminaConfig:
    """Parse a YAML file and return :class:`AdminaConfig`."""
    logger.info("Loading config from %s", path)
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"admina.yaml must be a YAML mapping, got {type(data).__name__}")
    return _build_from_yaml(data)

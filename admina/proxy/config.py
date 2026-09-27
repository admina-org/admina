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

"""
Admina — Configuration & Data Models
"""

import warnings
from typing import Any

from pydantic import BaseModel, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from admina.core.config import GATEWAY_STREAM_MODES
from admina.core.types import EventType, GovernanceAction, RiskLevel
from admina.domains.agent_security.scan_policy import SCAN_ROLES, parse_scan_roles
from admina.domains.governance import normalize_guard_fail_mode


# ── Environment Config ──────────────────────────────────────
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Storage
    REDIS_URL: str = "redis://localhost:6379/0"
    CLICKHOUSE_HOST: str = "localhost"
    CLICKHOUSE_PORT: int = 8123
    CLICKHOUSE_DB: str = "admina"
    CLICKHOUSE_PASSWORD: str = ""

    # Forensic blackbox backend selection.
    #   "memory" (default): in-memory ledger, hashed and chained but
    #               LOST ON RESTART. Default so the proxy never writes
    #               files unbidden. Switch to "filesystem" or "s3" for
    #               persistence — that's an explicit operator decision.
    #   "filesystem": local JSON files with SHA-256 chained hashes, no
    #               external service required. Path: FORENSIC_BASE_DIR
    #               (must be set explicitly to opt in).
    #   "s3":       generic S3-compatible via boto3 — works with AWS S3,
    #               Cloudflare R2, Backblaze B2, SeaweedFS, Garage,
    #               Ceph RGW, and MinIO servers (via their S3 API).
    #               Configure via FORENSIC_S3_* env vars.
    FORENSIC_BACKEND: str = "memory"
    # Empty by default — when FORENSIC_BACKEND="filesystem" the operator
    # MUST set this. Bare-metal / k8s typical: /var/lib/admina/forensic
    # mounted as a persistent volume.
    FORENSIC_BASE_DIR: str = ""
    # Generic S3 settings (used when FORENSIC_BACKEND="s3"). All
    # standard boto3 / AWS env vars (AWS_ACCESS_KEY_ID, etc.) are also
    # honoured if the FORENSIC_S3_* equivalents are empty.
    FORENSIC_S3_ENDPOINT: str = ""  # e.g. http://seaweedfs:8333
    FORENSIC_S3_REGION: str = "us-east-1"
    FORENSIC_S3_ACCESS_KEY: str = ""
    FORENSIC_S3_SECRET_KEY: str = ""
    FORENSIC_S3_BUCKET: str = "forensic-blackbox"
    # Object Lock — when "true", every forensic record written to S3 is
    # locked in COMPLIANCE mode for FORENSIC_S3_LOCK_DAYS days. The bucket
    # MUST have been created with ObjectLockEnabledForBucket=true (set
    # FORENSIC_S3_LOCK_AUTO_BUCKET=true to do this automatically the
    # first time the proxy starts and the bucket does not exist).
    # WORM = Write Once Read Many — required for many compliance regimes
    # (eIDAS, EU AI Act forensic evidence, FINRA, HIPAA).
    FORENSIC_S3_LOCK: bool = False
    FORENSIC_S3_LOCK_DAYS: int = 365 * 7  # default: 7 years
    FORENSIC_S3_LOCK_AUTO_BUCKET: bool = False
    # Retry / backoff for transient S3 failures (network blip, throttling).
    FORENSIC_S3_MAX_RETRIES: int = 5
    FORENSIC_S3_BASE_DELAY_S: float = 0.2

    # Telemetry
    OTEL_ENDPOINT: str = "http://localhost:4317"

    # Proxy
    UPSTREAM_MCP_URL: str = "http://localhost:9000"
    LOG_LEVEL: str = "INFO"
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:8080"

    # Auth — set a strong random key in production: openssl rand -hex 32
    # If empty, protected routes are refused (fail-closed) unless
    # ALLOW_UNAUTHENTICATED=true is set explicitly (local development only).
    ADMINA_API_KEY: str = ""
    ALLOW_UNAUTHENTICATED: bool = False
    # Force the `Secure` flag on the dashboard session cookie. The flag is
    # already set automatically when the request arrives over HTTPS; set
    # DASHBOARD_COOKIE_SECURE=true when TLS terminates at a reverse proxy
    # that does not forward the original scheme.
    DASHBOARD_COOKIE_SECURE: bool = False
    # Bundled dashboard (GET /, /vendor/*, sign-in at /api/dashboard/session).
    # false removes the SPA and browser sign-in; the /api/dashboard/* data
    # API stays available with the API key. `dashboard.enabled: false` in
    # admina.yaml has the same effect.
    ADMINA_DASHBOARD_ENABLED: bool = True
    # Lifetime in seconds of a dashboard browser session (60 s to 12 h).
    # The browser signs in again with the API key when it expires.
    ADMINA_DASHBOARD_SESSION_TTL: int = Field(default=3600, ge=60, le=43200)
    # Public OpenAPI documentation (/docs, /redoc, /openapi.json).
    ADMINA_API_DOCS_ENABLED: bool = True

    # Rate limiting (per session, requires Redis)
    RATE_LIMIT_MAX_REQUESTS: int = 100  # requests per window
    RATE_LIMIT_WINDOW_SECONDS: int = 60  # window in seconds
    RATE_LIMIT_IP_MULTIPLIER: int = 5  # IP limit = session limit * this

    # Governance mode — controls how the pipeline reacts to detections.
    #   "enforce" (default, recommended for production): block flagged
    #              requests, redact PII, raise alerts.
    #   "observe": never block. Run the full pipeline, log every decision
    #              with what would have happened, and let traffic through
    #              unchanged. Ideal for the first 1-2 weeks of a new
    #              deployment to tune thresholds without breaking users.
    #   "dry-run": same as observe but additionally tag the response so
    #              downstream tools know the request was analysed.
    # Restrictive default — opt out explicitly via ADMINA_GOVERNANCE_MODE=observe.
    # Read from ADMINA_GOVERNANCE_MODE (canonical name; the bare GOVERNANCE_MODE
    # env var is not accepted).
    GOVERNANCE_MODE: str = Field(default="enforce", validation_alias="ADMINA_GOVERNANCE_MODE")

    # Governance thresholds
    LOOP_WINDOW_SIZE: int = 10
    LOOP_SIMILARITY_THRESHOLD: float = 0.85
    LOOP_MAX_CONSECUTIVE: int = 3
    INJECTION_FAST_PATH_ENABLED: bool = True
    INJECTION_DEEP_PATH_ENABLED: bool = True
    PII_REDACTION_ENABLED: bool = True
    # Longest request content accepted on /mcp, estimated as its length in
    # characters (0 = no limit). Longer requests get 413.
    MAX_REQUEST_TOKENS: int = 100000
    # Largest request body accepted on any route, in bytes (0 = no limit).
    # A larger body gets 413 before it is parsed: at once when its
    # Content-Length is over the limit, otherwise as soon as the bytes read
    # go over it.
    ADMINA_MAX_REQUEST_BYTES: int = Field(default=10 * 1024 * 1024, ge=0)

    # Guard fail mode (B3): what happens when a governance guard raises.
    #   "open" (default): the guard is skipped, recorded as an ERROR check,
    #           and the pipeline continues — a crashing third-party guard
    #           must not take the whole pipeline down by default.
    #   "closed": a guard exception yields BLOCK.
    # Read from ADMINA_GUARD_FAIL_MODE (canonical name, shared with the SDK).
    GUARD_FAIL_MODE: str = Field(default="open", validation_alias="ADMINA_GUARD_FAIL_MODE")

    # ── OpenAI-compatible gateway (A3) ───────────────────────────
    # Upstream OpenAI-compatible API the gateway forwards to (Ollama,
    # vLLM, OpenAI, …). Must include the API base path (typically /v1).
    ADMINA_GATEWAY_UPSTREAM: str = "http://localhost:11434/v1"
    # Named upstream routes, "name=url[,name=url…]" (route names: lowercase
    # letters, digits and "_"). When set, it replaces gateway.upstreams of
    # admina.yaml. With neither, the gateway has one route, "default", to
    # ADMINA_GATEWAY_UPSTREAM. A request picks a route with the
    # X-Admina-Upstream header (unknown name → 400); without the header the
    # gateway uses gateway.default_upstream, or else the first route.
    ADMINA_GATEWAY_UPSTREAMS: str = ""
    # API key sent upstream as "Authorization: Bearer <key>" on every route
    # without a key of its own; empty = no Authorization header. Or set
    # ADMINA_GATEWAY_UPSTREAM_API_KEY_FILE to a file holding the key (read
    # once at startup, one trailing newline removed), not both. A route's own
    # key: ADMINA_GATEWAY_UPSTREAM_<NAME>_API_KEY[_FILE] (NAME = route name in
    # upper case), else api_key_file of the route in admina.yaml.
    ADMINA_GATEWAY_UPSTREAM_API_KEY: SecretStr = SecretStr("")
    ADMINA_GATEWAY_UPSTREAM_API_KEY_FILE: str = ""
    # Content returned to the caller when governance blocks a request,
    # shaped as an OpenAI completion with finish_reason="content_filter".
    ADMINA_GATEWAY_BLOCK_MESSAGE: str = "This request was blocked by the Admina governance policy."
    # Longest message text accepted on the gateway's chat completions, in
    # characters: the text of every message, as scanned (0 = no limit).
    # Longer requests get 413 before any governance check.
    ADMINA_GATEWAY_MAX_PROMPT_CHARS: int = Field(default=0, ge=0)
    # Optional comma-separated allow-list applied to GET /v1/models.
    # Empty = passthrough of the upstream's full model list.
    ADMINA_GATEWAY_MODELS_ALLOWLIST: str = ""
    # How streamed chat completions (stream=true) are relayed:
    #   "passthrough": the upstream bytes are forwarded unchanged, each SSE
    #       event as soon as it is complete, while no response transformation
    #       is active (PII_REDACTION_ENABLED=false); otherwise as "governed".
    #   "governed": each SSE chunk is parsed, transformed and re-serialised.
    # Empty = gateway.stream_mode of admina.yaml, else "passthrough".
    ADMINA_GATEWAY_STREAM_MODE: str = ""
    # Upstream timeouts of the gateway, in seconds (0 = no limit):
    #   CONNECT: opening a connection, or waiting for a free one in the pool;
    #   READ: waiting for the next bytes from the upstream (also bounds
    #         each write of the request);
    #   TOTAL: the whole upstream exchange, from sending the request to the
    #          last byte of the response.
    # A timeout before the response starts gets 504; during a stream, one
    # SSE error event ends the stream (without data: [DONE]).
    ADMINA_GATEWAY_TIMEOUT_CONNECT: float = Field(default=30.0, ge=0)
    ADMINA_GATEWAY_TIMEOUT_READ: float = Field(default=30.0, ge=0)
    ADMINA_GATEWAY_TIMEOUT_TOTAL: float = Field(default=0.0, ge=0)
    # Connection pool of the gateway's upstream client (all routes).
    ADMINA_GATEWAY_MAX_CONNECTIONS: int = Field(default=100, ge=1)
    ADMINA_GATEWAY_MAX_KEEPALIVE_CONNECTIONS: int = Field(default=20, ge=0)
    # Message roles the gateway's firewall scans, comma-separated, among
    # system, user, assistant and tool (empty = all four). Messages with any
    # other role are always scanned. A request can narrow the scan further
    # with X-Admina-Scan-Policy, never widen it.
    ADMINA_GATEWAY_SCAN_ROLES: str = ",".join(SCAN_ROLES)

    @field_validator("ADMINA_GATEWAY_SCAN_ROLES")
    @classmethod
    def validate_gateway_scan_roles(cls, v: str) -> str:
        roles = parse_scan_roles(v)
        return ",".join(role for role in SCAN_ROLES if role in roles)

    @field_validator("ADMINA_GATEWAY_STREAM_MODE")
    @classmethod
    def validate_gateway_stream_mode(cls, v: str) -> str:
        v = v.strip().lower()
        if v and v not in GATEWAY_STREAM_MODES:
            raise ValueError(
                "ADMINA_GATEWAY_STREAM_MODE must be one of: "
                f"{' | '.join(GATEWAY_STREAM_MODES)} (got {v!r})"
            )
        return v

    @field_validator("GOVERNANCE_MODE")
    @classmethod
    def validate_governance_mode(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"enforce", "observe", "dry-run", "dry_run"}:
            raise ValueError(
                f"GOVERNANCE_MODE must be one of: enforce | observe | dry-run (got {v!r})"
            )
        return "dry-run" if v == "dry_run" else v

    @field_validator("GUARD_FAIL_MODE")
    @classmethod
    def validate_guard_fail_mode(cls, v: str) -> str:
        return normalize_guard_fail_mode(v)

    @field_validator("FORENSIC_BACKEND")
    @classmethod
    def validate_forensic_backend(cls, v: str) -> str:
        v = v.lower().strip()
        if v == "minio":
            # The legacy minio-SDK backend was removed in 0.9.5. MinIO servers
            # speak the S3 API, so transparently route to the s3 backend and
            # tell the operator to migrate the MINIO_* env vars to FORENSIC_S3_*.
            warnings.warn(
                "FORENSIC_BACKEND='minio' is removed in 0.9.5 — using the 's3' "
                "backend instead. Point your MinIO server at FORENSIC_S3_ENDPOINT "
                "and set FORENSIC_S3_ACCESS_KEY / FORENSIC_S3_SECRET_KEY / "
                "FORENSIC_S3_BUCKET.",
                stacklevel=2,
            )
            return "s3"
        if v not in {"memory", "filesystem", "s3"}:
            raise ValueError(f"FORENSIC_BACKEND must be 'memory' | 'filesystem' | 's3' (got {v!r})")
        return v

    @field_validator("CORS_ORIGINS")
    @classmethod
    def warn_wildcard_cors(cls, v: str) -> str:
        origins = [o.strip() for o in v.split(",")]
        if "*" in origins:
            warnings.warn(
                "CORS_ORIGINS contains '*' — this allows any domain to make "
                "cross-origin requests to the proxy. Use specific origins in production.",
                stacklevel=2,
            )
        return v

    @field_validator("ADMINA_API_KEY")
    @classmethod
    def warn_short_api_key(cls, v: str) -> str:
        if v and len(v) < 16:
            warnings.warn(
                "ADMINA_API_KEY is shorter than 16 characters — use a stronger key in production",
                stacklevel=2,
            )
        return v


settings = Settings()


# ── MCP Protocol Models ─────────────────────────────────────
class MCPRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = None
    method: str
    params: dict[str, Any] | None = None


class MCPResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = None
    result: Any | None = None
    error: dict[str, Any] | None = None


# ── Governance Event ─────────────────────────────────────────
class GovernanceEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: EventType
    agent_id: str = "unknown"
    session_id: str = "unknown"
    method: str = ""
    tool_name: str = ""
    action: GovernanceAction = GovernanceAction.ALLOW
    risk_level: RiskLevel = RiskLevel.LOW
    details: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = 0.0
    request_hash: str = ""
    response_hash: str = ""

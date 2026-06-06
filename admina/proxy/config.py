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

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from admina.core.types import EventType, GovernanceAction, RiskLevel


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
    # If empty, auth is disabled (local development only).
    ADMINA_API_KEY: str = ""
    ALLOW_UNAUTHENTICATED: bool = False

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
    GOVERNANCE_MODE: str = "enforce"

    # Governance thresholds
    LOOP_WINDOW_SIZE: int = 10
    LOOP_SIMILARITY_THRESHOLD: float = 0.85
    LOOP_MAX_CONSECUTIVE: int = 3
    INJECTION_FAST_PATH_ENABLED: bool = True
    INJECTION_DEEP_PATH_ENABLED: bool = True
    PII_REDACTION_ENABLED: bool = True
    MAX_REQUEST_TOKENS: int = 100000

    @field_validator("GOVERNANCE_MODE")
    @classmethod
    def validate_governance_mode(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"enforce", "observe", "dry-run", "dry_run"}:
            raise ValueError(
                f"GOVERNANCE_MODE must be one of: enforce | observe | dry-run (got {v!r})"
            )
        return "dry-run" if v == "dry_run" else v

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

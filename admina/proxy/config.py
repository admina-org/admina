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
from typing import Any, Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from admina.core.config import GATEWAY_STREAM_MODES
from admina.core.secretfile import resolve_secret
from admina.core.types import EventType, GovernanceAction, RiskLevel
from admina.domains.agent_security.scan_policy import SCAN_ROLES, parse_scan_roles
from admina.domains.compliance.forensic import FAIL_MODES as FORENSIC_FAIL_MODES
from admina.domains.governance import normalize_guard_fail_mode
from admina.proxy.dashboard_session import parse_cookie_secure
from admina.proxy.gateway_body import forward_field_names
from admina.proxy.gateway_correlation import (
    forward_header_names,
    record_header_names,
    request_id_header_name,
)
from admina.proxy.log_format import LOG_FORMATS
from admina.proxy.surfaces import parse_surfaces


# ── Environment Config ──────────────────────────────────────
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # Validation errors name the setting, never its value (keys included).
        hide_input_in_errors=True,
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
    # FORENSIC_BACKEND and FORENSIC_BASE_DIR, when set, win over
    # domains.compliance.forensic.backend (or storage) and base_dir of
    # admina.yaml (see admina.proxy.forensic_backend).
    # What the proxy does when a forensic record cannot be written:
    #   "open" (default): the failure is logged and the request is served
    #       without its record;
    #   "closed": the request is answered 503 and not forwarded (gateway,
    #       /mcp), /api/v1/validate answers 503 until a record is written
    #       again, and a filesystem or S3 backend that cannot be opened (no
    #       directory, a directory that cannot be written, S3 not reachable)
    #       stops the proxy at startup.
    # In "open" mode such a backend is reported at startup and by /health
    # (forensic_writable false, status degraded); nothing is recorded, in
    # memory either, until it is fixed.
    ADMINA_FORENSIC_FAIL_MODE: str = "open"

    # Telemetry. OTEL_ENABLED=true (default): the proxy exports a span per
    # governance decision to OTEL_ENDPOINT (OTLP gRPC) when the telemetry
    # extra is installed and ADMINA_OFFLINE is off. false: no exporter is
    # built and nothing is exported.
    OTEL_ENABLED: bool = True
    OTEL_ENDPOINT: str = "http://localhost:4317"

    # Proxy
    UPSTREAM_MCP_URL: str = "http://localhost:9000"
    LOG_LEVEL: str = "INFO"
    # Log output: "text" (default) or "json", one JSON object per line with
    # timestamp, level, logger, message and, if any, the exception text.
    ADMINA_LOG_FORMAT: str = LOG_FORMATS[0]
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:8080"

    # Auth — set a strong random key in production: openssl rand -hex 32
    # If empty, protected routes are refused (fail-closed) unless
    # ALLOW_UNAUTHENTICATED=true is set explicitly (local development only).
    ADMINA_API_KEY: str = ""
    # Or a file holding the key (a Docker or Kubernetes secret, for example):
    # read once at startup, one trailing newline removed. Set the key or the
    # file, not both; a missing, unreadable or empty file stops the proxy.
    ADMINA_API_KEY_FILE: str = ""
    ALLOW_UNAUTHENTICATED: bool = False
    # A key accepted by POST /api/v1/audit only (appending audit records),
    # besides the API key; any other route refuses it. Empty (default): the
    # route needs the API key, like every other route. Or set
    # ADMINA_AUDIT_APPEND_KEY_FILE to a file holding the key, not both.
    ADMINA_AUDIT_APPEND_KEY: str = ""
    ADMINA_AUDIT_APPEND_KEY_FILE: str = ""
    # `Secure` flag of the dashboard session cookie. It is always set when the
    # request arrives over HTTPS. Over plain HTTP:
    #   false (default): not set;
    #   auto: set unless the dashboard is addressed as localhost, *.localhost
    #         or a loopback address (a browser does not keep a Secure cookie
    #         received on any other plain http:// address);
    #   true: always set, e.g. when TLS terminates at a reverse proxy that
    #         does not forward the original scheme.
    DASHBOARD_COOKIE_SECURE: bool | Literal["auto"] = False
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
    # true: the OpenAPI documentation needs the API key, like every other
    # route (default false: public).
    ADMINA_API_DOCS_REQUIRE_AUTH: bool = False
    # true: GET /metrics needs the API key (default false: public).
    ADMINA_METRICS_REQUIRE_AUTH: bool = False
    # Surfaces the proxy serves, comma-separated (empty = all of them):
    #   gateway      /v1/* (OpenAI-compatible gateway)
    #   mcp          /mcp, /mcp/*
    #   integration  /api/v1/*
    #   compliance   /api/compliance/*
    #   dashboard    /api/dashboard/*, /api/stats, /api/events, the dashboard
    #                shell (/, /vendor/*) and its browser sign-in
    # A disabled surface answers 404 (before authentication) and its routes
    # are not mounted. /health and /metrics are always served.
    ADMINA_ENABLED_SURFACES: str = ""
    # Configuration check at startup. A value of the wrong type in
    # admina.yaml always stops the proxy. Unknown keys of admina.yaml and
    # ADMINA_* variables (environment or .env) that nothing reads are:
    #   false (default): logged as a warning;
    #   true: an error, and the proxy does not start.
    ADMINA_CONFIG_STRICT: bool = False
    # Comma-separated prefixes of ADMINA_* variables that belong to other
    # components sharing the environment (e.g. ADMINA_MYAPP_): not reported.
    # A plugin's entry point name gives one too (ADMINA_<NAME>_).
    ADMINA_ENV_ALLOW_PREFIXES: str = ""

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
    # False turns off the firewall's deep path (heuristic scoring), on
    # either engine: a text is then flagged by the patterns only.
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
    # HTTP status of a blocked chat completion:
    #   200: a completion carrying ADMINA_GATEWAY_BLOCK_MESSAGE (a stream of
    #        one chunk and data: [DONE] for stream=true);
    #   403: {"error": {"message": <ADMINA_GATEWAY_BLOCK_MESSAGE>,
    #        "type": "governance_blocked", "param": null,
    #        "code": "governance_blocked", "categories": [...]}}, streaming or not.
    # Either way the response has X-Admina-Action: BLOCK.
    ADMINA_GATEWAY_BLOCK_STATUS: int = 200
    # Header whose value the gateway records as request_id (e.g.
    # X-Request-Id; at most 128 characters). Empty = none: request_id is null.
    ADMINA_GATEWAY_REQUEST_ID_HEADER: str = ""
    # Comma-separated request headers recorded in the context of the
    # forensic record (lower-case name -> value, at most 128 characters).
    # Headers not listed are never recorded. Credentials cannot be listed.
    ADMINA_GATEWAY_RECORD_HEADERS: str = ""
    # Comma-separated request headers forwarded upstream (e.g.
    # traceparent,tracestate,X-Request-Id). traceparent and tracestate are
    # forwarded only with a valid W3C trace context. The upstream receives
    # nothing else from the client. Credentials, connection and body headers
    # and X-Admina-* cannot be listed.
    ADMINA_GATEWAY_FORWARD_HEADERS: str = ""
    # Longest message text accepted on the gateway's chat completions, in
    # characters: the text of every message, as scanned (0 = no limit).
    # Longer requests get 413 before any governance check.
    ADMINA_GATEWAY_MAX_PROMPT_CHARS: int = Field(default=0, ge=0)
    # Optional comma-separated allow-list of model ids: GET /v1/models lists
    # only these, and POST /v1/chat/completions for any other model gets 403
    # (code model_not_allowed) before it is governed or forwarded.
    # Empty = every model, and the upstream's full model list.
    ADMINA_GATEWAY_MODELS_ALLOWLIST: str = ""
    # Top-level fields of a chat completion request forwarded upstream,
    # comma-separated and case-sensitive (empty = every field, as received).
    # model, messages and stream are always forwarded, and so are the fields
    # of the limits below that are set; other fields not listed are left out.
    # The firewall still scans the request as received.
    ADMINA_GATEWAY_FORWARD_FIELDS: str = ""
    # Largest n (choices) forwarded upstream (0 = no limit): a larger n is
    # lowered to it.
    ADMINA_GATEWAY_MAX_N: int = Field(default=0, ge=0)
    # Largest max_tokens and max_completion_tokens forwarded upstream
    # (0 = no limit): larger values are lowered to it, and a request that
    # sets neither is forwarded with max_tokens set to it.
    # While a limit is set, the fields it applies to must be absent, null or
    # an integer of at least 1; any other value gets 400 (code invalid_value)
    # before any governance check. These three settings never change the
    # messages.
    ADMINA_GATEWAY_MAX_COMPLETION_TOKENS: int = Field(default=0, ge=0)
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
    # Honour X-Admina-Scan-Policy. Off: the header is ignored and every
    # request is scanned in full. On: any caller that holds the API key can
    # narrow the scan of its own requests, down to leaving out every user
    # message (the active ruleset is public), so turn it on only when every
    # such caller is trusted to scan what it declares as scanned.
    ADMINA_GATEWAY_SCAN_POLICY_ENABLED: bool = False
    # The gateway runs the governance pipeline (firewall, PII redaction,
    # guards) and the PII redaction of completions in a pool of worker
    # threads, off the event loop.
    #   WORKERS: threads in the pool, the most requests governed at once
    #       (0 = the number of CPUs); further requests wait for a thread.
    #   TIMEOUT: seconds a request waits for its governance decision, the
    #       wait for a thread included (0 = no limit). Past it the request
    #       is blocked, in every governance mode, and recorded; so is a
    #       request whose pipeline raises.
    ADMINA_GATEWAY_PIPELINE_WORKERS: int = Field(default=0, ge=0)
    ADMINA_GATEWAY_PIPELINE_TIMEOUT: float = Field(default=0.0, ge=0)
    # Run the firewall on the completion text too (needs the firewall on).
    # A non-streaming completion is scanned before it is returned and, when
    # flagged in enforce mode, replaced by the block message; a streamed one
    # is scanned when the stream ends and the result is only recorded.
    ADMINA_GATEWAY_SCAN_RESPONSE: bool = False

    @field_validator("DASHBOARD_COOKIE_SECURE", mode="before")
    @classmethod
    def validate_dashboard_cookie_secure(cls, v: object) -> bool | str:
        return parse_cookie_secure(v)

    @field_validator("ADMINA_ENABLED_SURFACES")
    @classmethod
    def validate_enabled_surfaces(cls, v: str) -> str:
        return ",".join(parse_surfaces(v))

    @field_validator("ADMINA_LOG_FORMAT")
    @classmethod
    def validate_log_format(cls, v: str) -> str:
        v = v.strip().lower() or LOG_FORMATS[0]
        if v not in LOG_FORMATS:
            raise ValueError(
                f"ADMINA_LOG_FORMAT must be one of: {' | '.join(LOG_FORMATS)} (got {v!r})"
            )
        return v

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

    @field_validator("ADMINA_GATEWAY_BLOCK_STATUS")
    @classmethod
    def validate_gateway_block_status(cls, v: int) -> int:
        if v not in (200, 403):
            raise ValueError(f"ADMINA_GATEWAY_BLOCK_STATUS must be 200 or 403 (got {v})")
        return v

    @field_validator("ADMINA_GATEWAY_REQUEST_ID_HEADER")
    @classmethod
    def validate_gateway_request_id_header(cls, v: str) -> str:
        return request_id_header_name(v)

    @field_validator("ADMINA_GATEWAY_RECORD_HEADERS")
    @classmethod
    def validate_gateway_record_headers(cls, v: str) -> str:
        return ",".join(record_header_names(v))

    @field_validator("ADMINA_GATEWAY_FORWARD_HEADERS")
    @classmethod
    def validate_gateway_forward_headers(cls, v: str) -> str:
        return ",".join(forward_header_names(v))

    @field_validator("ADMINA_GATEWAY_FORWARD_FIELDS")
    @classmethod
    def validate_gateway_forward_fields(cls, v: str) -> str:
        return ",".join(forward_field_names(v))

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

    @field_validator("ADMINA_FORENSIC_FAIL_MODE")
    @classmethod
    def validate_forensic_fail_mode(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in FORENSIC_FAIL_MODES:
            raise ValueError(
                "ADMINA_FORENSIC_FAIL_MODE must be one of: "
                f"{' | '.join(FORENSIC_FAIL_MODES)} (got {v!r})"
            )
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
        _warn_if_short_api_key(v)
        return v

    @model_validator(mode="after")
    def read_api_key_file(self) -> "Settings":
        """Take ADMINA_API_KEY from ADMINA_API_KEY_FILE when that is set."""
        if self.ADMINA_API_KEY_FILE:
            key = resolve_secret(
                self.ADMINA_API_KEY, self.ADMINA_API_KEY_FILE, setting="ADMINA_API_KEY"
            )
            _warn_if_short_api_key(key or "")
            self.ADMINA_API_KEY = key or ""
        return self

    @model_validator(mode="after")
    def read_audit_append_key_file(self) -> "Settings":
        """Take ADMINA_AUDIT_APPEND_KEY from its _FILE when that is set."""
        if self.ADMINA_AUDIT_APPEND_KEY_FILE:
            key = resolve_secret(
                self.ADMINA_AUDIT_APPEND_KEY,
                self.ADMINA_AUDIT_APPEND_KEY_FILE,
                setting="ADMINA_AUDIT_APPEND_KEY",
            )
            self.ADMINA_AUDIT_APPEND_KEY = key or ""
        return self


def _warn_if_short_api_key(key: str) -> None:
    if key and len(key) < 16:
        warnings.warn(
            "ADMINA_API_KEY is shorter than 16 characters — use a stronger key in production",
            stacklevel=3,
        )


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

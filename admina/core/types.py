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

"""Admina — Protocol-agnostic governance types.

These dataclasses decouple the governance engine from any wire format.
Transport adapters (MCP, A2A, AG-UI, REST) convert to/from these types.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

__all__ = [
    "RiskLevel",
    "GovernanceAction",
    "EventType",
    "GovernanceRequest",
    "GovernanceResponse",
    "NetworkAttempt",
    "SandboxError",
    "SandboxFile",
    "SandboxLimits",
    "SandboxNetwork",
    "SandboxRequest",
    "SandboxRequestInvalid",
    "SandboxResult",
    "SandboxUnavailable",
]


class RiskLevel(str, Enum):
    """Risk severity levels used across all governance domains.

    Using ``str`` mixin so values serialise directly to JSON strings.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GovernanceAction(str, Enum):
    """Actions the governance engine can take on a request."""

    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    ESCALATE = "escalate"
    CIRCUIT_BREAK = "circuit_break"


class EventType(str, Enum):
    """Unified event types used across proxy and SDK."""

    # Proxy / MCP events
    MCP_REQUEST = "mcp_request"
    MCP_RESPONSE = "mcp_response"
    GATEWAY_REQUEST = "gateway_request"
    # The completion record of a gateway call (same event_id as its request).
    GATEWAY_RESPONSE = "gateway_response"
    GATEWAY_RESPONSE_SCAN = "gateway_response_scan"
    # A request of POST /api/v1/validate (a ClickHouse row; no forensic record).
    VALIDATE_REQUEST = "validate_request"
    INJECTION_DETECTED = "injection_detected"
    PII_REDACTED = "pii_redacted"
    LOOP_DETECTED = "loop_detected"
    POLICY_VIOLATION = "policy_violation"
    CIRCUIT_BREAK = "circuit_break"
    # The forensic chain state was rebuilt from verified records at startup.
    CHAIN_STATE_REBUILT = "chain_state_rebuilt"
    # A tool call executed by an execution sandbox (record <event_id>:sandbox).
    SANDBOX_EXECUTION = "sandbox_execution"

    # SDK / framework events
    MODEL_CALL = "model.call"
    MODEL_RESPONSE = "model.response"
    DATA_ACCESS = "data.access"
    DATA_CLASSIFY = "data.classify"
    DATA_REDACT = "data.redact"
    AGENT_REQUEST = "agent.request"
    AGENT_RESPONSE = "agent.response"
    GOVERNANCE_DECISION = "governance.decision"
    COMPLIANCE_CHECK = "compliance.check"


@dataclass
class GovernanceRequest:
    """A protocol-agnostic inbound request to the governance engine.

    Transport adapters normalize protocol-specific messages into this
    dataclass before the governance pipeline processes them.
    """

    content: str
    method: str = ""
    direction: Literal["inbound", "outbound"] = "inbound"
    session_id: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    protocol: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: Any = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_us: float = field(default_factory=lambda: time.time() * 1_000_000)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (excluding ``raw``)."""
        return {
            "request_id": self.request_id,
            "content": self.content,
            "method": self.method,
            "direction": self.direction,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "protocol": self.protocol,
            "metadata": self.metadata,
            "timestamp_us": self.timestamp_us,
        }


@dataclass
class GovernanceResponse:
    """The governance engine's decision for a single request.

    Returned by the governance pipeline and converted back to wire format
    by the transport adapter.
    """

    content: str
    action: Literal["ALLOW", "BLOCK", "REDACT", "CIRCUIT_BREAK"] = "ALLOW"
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    domain: str = ""
    latency_us: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    request_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "request_id": self.request_id,
            "content": self.content,
            "action": self.action,
            "risk_level": self.risk_level,
            "domain": self.domain,
            "latency_us": self.latency_us,
            "metadata": self.metadata,
        }


# ── Execution sandbox ────────────────────────────────────────
#
# The contract of the ``execution_sandbox`` plugins
# (:class:`admina.plugins.base.BaseExecutionSandbox`). Typed rather than
# dicts: the limits and the result are a security contract, and a misspelt
# key in a dict would be ignored without a word.


class SandboxNetwork(str, Enum):
    """The network of a sandboxed execution."""

    #: No interface other than loopback.
    NONE = "none"
    #: Outbound traffic through an egress proxy that applies the allowlist.
    #: Declared for providers that support it; the built-in Docker sandbox
    #: does not yet.
    EGRESS = "egress"


@dataclass(frozen=True)
class SandboxLimits:
    """The resources of one execution."""

    #: Wall clock, enforced by the caller of the environment.
    timeout_s: float = 30.0
    #: Memory, swap included (no swap).
    memory_mb: int = 256
    cpus: float = 1.0
    #: Processes and threads.
    pids: int = 128
    #: Size of the writable working directory (/work).
    disk_mb: int = 64
    #: Kept of stdout, and of stderr; the rest is discarded.
    output_max_bytes: int = 65_536
    #: Total of the input files, and of the output files.
    files_max_bytes: int = 8 << 20


@dataclass(frozen=True)
class SandboxFile:
    """A file of the working directory: *path* is relative to /work (no
    absolute path, no ``..``)."""

    path: str
    content: bytes


@dataclass(frozen=True)
class SandboxRequest:
    """One execution, already allowed by the governance pipeline.

    There is no field for mounts, capabilities, privileges or the runtime:
    those come from the provider's configuration only.
    """

    #: argv, never a string for a shell.
    command: tuple[str, ...]
    stdin: bytes = b""
    files: tuple[SandboxFile, ...] = ()
    #: The whole environment of the command: nothing else is passed.
    env: Mapping[str, str] = field(default_factory=dict)
    #: None: the provider's default image.
    image: str | None = None
    limits: SandboxLimits = field(default_factory=SandboxLimits)
    network: SandboxNetwork = SandboxNetwork.NONE
    #: Directories under /work whose files are returned.
    collect: tuple[str, ...] = ("out",)
    #: The event_id of the request, for labels and the forensic record.
    request_id: str = ""


@dataclass(frozen=True)
class NetworkAttempt:
    """A connection the sandboxed code attempted."""

    host: str
    port: int
    allowed: bool
    reason: str = ""


def _digest(data: bytes) -> dict[str, Any]:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


@dataclass
class SandboxResult:
    """What an execution produced. A timeout, a non-zero exit code or an
    out-of-memory kill are results (the code ran, contained); a failure of
    the environment itself is a :class:`SandboxError`."""

    #: None when the command was killed for its timeout.
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    files: tuple[SandboxFile, ...]
    #: The files returned are not all the files produced (over the limit,
    #: or they could not be read back).
    files_truncated: bool
    network_attempts: tuple[NetworkAttempt, ...]
    #: False: the provider cannot observe connection attempts.
    network_observed: bool
    duration_ms: float
    timed_out: bool
    oom_killed: bool
    #: e.g. ``docker/runc``, ``docker/runsc``.
    runtime: str
    image_digest: str

    def to_check(self) -> dict[str, Any]:
        """Summary for the forensic record (``checks.sandbox``): sizes and
        SHA-256 hashes, never the content of the output or of the files."""
        return {
            "runtime": self.runtime,
            "image_digest": self.image_digest,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "oom_killed": self.oom_killed,
            "duration_ms": round(self.duration_ms, 1),
            "stdout": {**_digest(self.stdout), "truncated": self.stdout_truncated},
            "stderr": {**_digest(self.stderr), "truncated": self.stderr_truncated},
            "files_out": [{"path": f.path, **_digest(f.content)} for f in self.files],
            "files_truncated": self.files_truncated,
            "network": {
                "observed": self.network_observed,
                "attempts": [
                    {"host": a.host, "port": a.port, "allowed": a.allowed}
                    for a in self.network_attempts
                ],
            },
        }


class SandboxError(Exception):
    """The sandbox could not execute the request (an infrastructure
    failure, not a failure of the code it runs)."""


class SandboxUnavailable(SandboxError):
    """The runtime is not reachable, the image is missing or a required
    capability is not supported."""


class SandboxRequestInvalid(SandboxError, ValueError):
    """The request was refused before anything was executed (a path, a
    size, an environment variable)."""

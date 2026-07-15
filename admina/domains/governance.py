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

"""Admina — Governance pipeline (canonical, surface-agnostic).

Orchestrates all governance checks (loop breaker, firewall, PII redaction,
pluggable guards) in sequence and returns a GovernanceResult.

This is the authoritative home of the governance pipeline. It is pure logic:
engines and guards are injected by the caller; there is no HTTP, no storage,
no I/O here. Imports only from :mod:`admina.core.types` — no dependency on
:mod:`admina.proxy` or any surface adapter.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from admina.core.types import GovernanceAction, RiskLevel
from admina.core.types import GovernanceResponse as GovResponse

logger = logging.getLogger("admina.proxy")

# Recursion cap: DoS protection against deeply nested payloads.
_MAX_SCAN_DEPTH = 6


def normalize_guard_fail_mode(value: str | None) -> str:
    """Normalize the guard fail-mode setting to ``"open"`` or ``"closed"``.

    ``"open"`` (default): a guard that raises its contract is skipped and
    recorded as an ``ERROR`` check; the pipeline continues. ``"closed"``:
    a guard exception yields ``action=BLOCK``. ``None`` and the empty string
    resolve to ``"open"``. Any other value raises ``ValueError``.
    """
    normalized = (value or "open").strip().lower()
    if normalized not in ("open", "closed"):
        raise ValueError(f"guard fail mode must be 'open' or 'closed' (got {value!r})")
    return normalized


@dataclass
class GovernanceResult:
    """Result of running the full governance pipeline on a request."""

    action: GovernanceAction = GovernanceAction.ALLOW
    risk_level: RiskLevel = RiskLevel.LOW
    checks: dict[str, Any] = field(default_factory=dict)
    redacted_body: dict | None = None
    gov_response: GovResponse | None = None
    latency_ms: float = 0.0
    # Set in observe / dry-run mode: the action that *would* have been taken
    # in enforce mode. Useful for dashboards and policy tuning.
    would_action: GovernanceAction | None = None
    mode: str = "enforce"


async def run_pipeline(
    *,
    body: dict,
    content_str: str,
    session_id: str,
    agent_id: str,
    request_id: str,
    params: dict,
    firewall: Any,
    pii_redactor: Any,
    loop_breaker: Any,
    governance_guards: list,
    injection_enabled: bool = True,
    pii_enabled: bool = True,
    loop_enabled: bool = True,
    mode: str = "enforce",
    guard_fail_mode: str = "open",
) -> GovernanceResult:
    """Execute the full governance pipeline and return a GovernanceResult.

    This function is pure logic — no HTTP, no storage, no side effects.
    The caller (mcp_proxy) handles rate limiting, forensic storage,
    ClickHouse, event bus, and HTTP responses.

    ``loop_enabled`` controls whether the loop-breaker stage runs.  Set to
    ``False`` for single-shot callers (e.g. GovernedModel) that have no
    cross-call session state; the stage is skipped and ``loop_result`` is
    set to a no-op dict so downstream code is unaffected.

    ``guard_fail_mode`` selects request-side behavior when a governance guard
    raises: ``"open"`` (default) records an ``ERROR`` check and continues;
    ``"closed"`` sets ``action=BLOCK`` (risk HIGH) while still recording the
    ``ERROR`` check.
    """
    start_time = time.perf_counter()
    result = GovernanceResult()
    result.redacted_body = body
    result.mode = mode

    # 1. Loop Breaker
    if loop_enabled:
        loop_result = loop_breaker.check(session_id, content_str)
        result.checks["loop_breaker"] = loop_result
        if loop_result["is_loop"]:
            result.action = GovernanceAction.CIRCUIT_BREAK
            result.risk_level = RiskLevel.HIGH
    else:
        loop_result = {"is_loop": False, "similarity": None}

    # 2. Anti-Injection Firewall
    if result.action != GovernanceAction.CIRCUIT_BREAK and injection_enabled:
        texts_to_scan = _extract_text_fields(body)
        for text in texts_to_scan:
            fw_result = firewall.check(text)
            result.checks["firewall"] = fw_result
            if fw_result["is_injection"]:
                result.action = GovernanceAction.BLOCK
                result.risk_level = fw_result["risk_level"]
                break

    # 3. PII Redaction
    pii_count = 0
    if result.action == GovernanceAction.ALLOW and pii_enabled:
        redacted_params, pii_result = _redact_params(params, pii_redactor)
        result.checks["pii_redaction"] = pii_result
        pii_count = pii_result["count"]
        if pii_count > 0:
            result.redacted_body = {**body, "params": redacted_params}

    # 4. Pluggable Governance Guards
    if result.action == GovernanceAction.ALLOW and governance_guards:
        guard_payload = {"content": content_str, "params": params}
        for guard in governance_guards:
            try:
                guard_result = await guard.inspect_request(guard_payload)
                result.checks[f"guard_{guard.name}"] = guard_result
                if guard_result.get("action") in ("BLOCK", "REDACT"):
                    result.action = GovernanceAction.BLOCK
                    result.risk_level = guard_result.get("risk_level", RiskLevel.HIGH)
                    break
            except (ValueError, RuntimeError, OSError, TypeError) as exc:
                logger.error(
                    "Guard %r failed its contract and was skipped: %s",
                    guard.name,
                    exc,
                    exc_info=True,
                )
                result.checks[f"guard_{guard.name}"] = {
                    "action": "ERROR",
                    "error": str(exc),
                }
                if guard_fail_mode == "closed":
                    # Fail-closed: a guard that breaks its contract blocks the
                    # request. The ERROR entry above stays as the audit trail.
                    result.action = GovernanceAction.BLOCK
                    result.risk_level = RiskLevel.HIGH
                    break

    # 5. Apply governance MODE — observe / dry-run downgrade BLOCK to ALLOW
    # but record what would have happened in `would_action` so dashboards
    # and the suggestion engine still see the policy decision.
    if mode in ("observe", "dry-run") and result.action in (
        GovernanceAction.BLOCK,
        GovernanceAction.CIRCUIT_BREAK,
    ):
        result.would_action = result.action
        logger.info(
            "[%s] would have %s (risk=%s) — pass-through",
            mode.upper(),
            result.action.value,
            result.risk_level,
        )
        result.action = GovernanceAction.ALLOW

    # 6. Compute latency
    result.latency_ms = (time.perf_counter() - start_time) * 1000

    # 7. Build GovernanceResponse
    result.gov_response = _build_gov_response(result, request_id, loop_result, pii_count)

    return result


# --- helpers (moved from proxy/main.py) ---


def _extract_text_fields(obj: Any, depth: int = 0) -> list[str]:
    """Recursively extract all string fields from a dict/list."""
    if depth > _MAX_SCAN_DEPTH:
        return []
    texts: list[str] = []
    if isinstance(obj, str):
        texts.append(obj)
    elif isinstance(obj, dict):
        # Scan keys as well as values: injection or PII in a field name is not skipped.
        for k, v in obj.items():
            texts.extend(_extract_text_fields(k, depth + 1))
            texts.extend(_extract_text_fields(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            texts.extend(_extract_text_fields(item, depth + 1))
    return texts


def _redact_params(params: dict, pii_redactor: Any) -> tuple[dict, dict]:
    """Redact PII from all string values in params."""
    total_result: dict[str, Any] = {"redacted_text": "", "entities": [], "count": 0}
    redacted = _deep_redact(params, total_result, pii_redactor)
    return redacted, total_result


def redact_response_result(result: Any, pii_redactor: Any) -> tuple[Any, int]:
    """Recursively PII-redact an MCP tool result (str | dict | list).

    Returns (redacted_result, pii_count). Mirrors the request-side deep
    redaction so dict-shaped results are not leaked.
    """
    acc: dict[str, Any] = {"redacted_text": "", "entities": [], "count": 0}
    redacted = _deep_redact(result, acc, pii_redactor)
    return redacted, acc["count"]


def _deep_redact(obj: Any, result: dict, pii_redactor: Any, depth: int = 0) -> Any:
    if depth > _MAX_SCAN_DEPTH:
        return obj
    if isinstance(obj, str):
        r = pii_redactor.redact(obj)
        result["entities"].extend(r["entities"])
        result["count"] += r["count"]
        return r["redacted_text"]
    elif isinstance(obj, dict):
        # Redact keys as well as values: injection or PII in a field name is not skipped.
        # Non-string keys (int, tuple, …) pass through _deep_redact unchanged (final return obj).
        # When two distinct keys redact to the same placeholder, disambiguate with a numeric
        # suffix so no value is silently dropped (data-loss guard).
        out: dict = {}
        for k, v in obj.items():
            rk = _deep_redact(k, result, pii_redactor, depth + 1)
            rv = _deep_redact(v, result, pii_redactor, depth + 1)
            if isinstance(rk, str) and rk in out:
                base, suffix = rk, 2
                while f"{base}#{suffix}" in out:
                    suffix += 1
                rk = f"{base}#{suffix}"
            out[rk] = rv
        return out
    elif isinstance(obj, list):
        return [_deep_redact(item, result, pii_redactor, depth + 1) for item in obj]
    return obj


def safe_serialize(obj: Any) -> Any:
    """Make object JSON-serializable."""
    if hasattr(obj, "value"):
        return obj.value
    return obj


def build_governance_details(result: GovernanceResult) -> dict:
    """Assemble the persisted governance details for forensic/analytics sinks.

    Mirrors the flat checks dict that was previously stored as ``details`` in
    ClickHouse and the forensic record, and adds ``would_action`` (the shadow
    decision) when set in observe/dry-run mode so downstream analytics can count
    would-have-blocked events.

    The returned dict is safe to pass directly as ``GovernanceEvent.details``.
    """
    details: dict[str, Any] = dict(result.checks)
    if result.would_action is not None:
        details["would_action"] = safe_serialize(result.would_action)
    return details


def _build_gov_response(
    result: GovernanceResult,
    request_id: str,
    loop_result: dict,
    pii_count: int,
) -> GovResponse:
    """Build a protocol-agnostic GovernanceResponse from pipeline results."""
    _guard_block = next(
        (
            k
            for k, v in result.checks.items()
            if k.startswith("guard_") and v.get("action") in ("BLOCK", "REDACT")
        ),
        None,
    )
    _deciding_domain = (
        "loop_breaker"
        if result.action == GovernanceAction.CIRCUIT_BREAK
        else (
            _guard_block.removeprefix("guard_")
            if _guard_block and result.action == GovernanceAction.BLOCK
            else (
                "firewall"
                if result.action == GovernanceAction.BLOCK
                else (
                    "pii" if result.checks.get("pii_redaction", {}).get("count", 0) > 0 else "none"
                )
            )
        )
    )
    _action_raw = result.action
    _risk_raw = result.risk_level
    return GovResponse(
        content=json.dumps(result.redacted_body, default=str),
        action=(_action_raw.value if hasattr(_action_raw, "value") else _action_raw).upper(),
        risk_level=(_risk_raw.value if hasattr(_risk_raw, "value") else _risk_raw).upper(),
        domain=_deciding_domain,
        latency_us=result.latency_ms * 1000,
        request_id=request_id,
        metadata={"similarity": loop_result.get("similarity")},
    )

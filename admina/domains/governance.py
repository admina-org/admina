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
no I/O here. Imports only from :mod:`admina.core.types` and
:mod:`admina.core.exception_log` — no dependency on :mod:`admina.proxy` or
any surface adapter.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from admina.core.exception_log import log_frames
from admina.core.types import GovernanceAction, RiskLevel
from admina.core.types import GovernanceResponse as GovResponse

logger = logging.getLogger("admina.proxy")

#: Deepest level of a request whose strings the pipeline scans and redacts
#: (the body is level 0), as :data:`~admina.domains.agent_security.
#: scan_policy.REQUEST_SCAN_DEPTH` for the gateway. Text nested deeper is
#: neither scanned nor redacted, and the pipeline refuses the request.
SCAN_DEPTH = 32
_MAX_SCAN_DEPTH = SCAN_DEPTH


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
    egress_policy: Any = None,
    egress_mode: str = "observe",
    scan_texts: list[str] | None = None,
    scan_truncated: bool = False,
    redact_params: Callable[[dict, Any], tuple[dict, dict]] | None = None,
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

    ``egress_policy`` is an :class:`~admina.domains.agent_security.egress.
    EgressPolicy` (or ``None`` to skip the stage entirely — the operator has
    disabled egress control). ``egress_mode`` is ``"observe"`` (default) or
    ``"enforce"``, typically produced by
    :func:`~admina.domains.agent_security.egress.resolve_egress_mode`.

    ``scan_texts`` are the texts the firewall scans; ``None`` (default)
    scans every string of ``body``, keys included, down to
    :data:`SCAN_DEPTH`: with the firewall or PII redaction on, text nested
    deeper blocks the request (``checks["scan_depth"]``) in ``enforce``
    mode. ``scan_truncated`` says
    that the caller left text out of ``scan_texts`` because it lies deeper
    than the caller's depth limit: with the firewall on, the request is then
    blocked (risk HIGH, ``checks["scan_depth"]``), in ``enforce`` mode.

    ``redact_params`` builds the redacted ``params`` and the PII result
    from ``params`` and the PII engine; ``None`` (default) redacts every
    string value of ``params``, never a key (:func:`_redact_params`). The
    gateway passes :func:`redact_chat_params`.
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

    # Text nested past SCAN_DEPTH is neither scanned nor redacted below.
    deep_text = scan_texts is None and (injection_enabled or pii_enabled) and _has_deep_text(body)

    # 2. Anti-Injection Firewall
    if result.action != GovernanceAction.CIRCUIT_BREAK and injection_enabled:
        texts_to_scan = _extract_text_fields(body) if scan_texts is None else scan_texts
        scan_truncated = scan_truncated or deep_text
        for text in texts_to_scan:
            fw_result = firewall.check(text)
            result.checks["firewall"] = fw_result
            if fw_result["is_injection"]:
                result.action = GovernanceAction.BLOCK
                result.risk_level = fw_result["risk_level"]
                break
        if scan_truncated:
            # Text past the caller's depth limit was not scanned: fail closed.
            result.checks["scan_depth"] = {"action": "BLOCK", "reason": "depth_limit_exceeded"}
            if result.action == GovernanceAction.ALLOW:
                result.action = GovernanceAction.BLOCK
                result.risk_level = RiskLevel.HIGH

    if deep_text and not injection_enabled and result.action == GovernanceAction.ALLOW:
        # PII redaction alone would leave the deep text as it is: fail closed.
        result.checks["scan_depth"] = {"action": "BLOCK", "reason": "depth_limit_exceeded"}
        result.action = GovernanceAction.BLOCK
        result.risk_level = RiskLevel.HIGH

    # 3. PII Redaction
    pii_count = 0
    if result.action == GovernanceAction.ALLOW and pii_enabled:
        redacted_params, pii_result = (redact_params or _redact_params)(params, pii_redactor)
        result.checks["pii_redaction"] = pii_result
        pii_count = pii_result["count"]
        if pii_count > 0:
            result.redacted_body = {**body, "params": redacted_params}

    # 3b. Egress policy — destination control, method-independent.
    #
    # Placement after PII is positional only: the PII stage above never
    # mutates `params` (it builds a separate `redacted_params` used only for
    # `result.redacted_body`), so this stage sees the same, unredacted
    # `params` a PII-before ordering would also see.
    #
    # Placement before the guards is the real constraint: a denied
    # destination must short-circuit third-party guard inspection, rather
    # than handing an unauthorised outbound call to plugin code.
    if result.action == GovernanceAction.ALLOW and egress_policy is not None:
        from admina.domains.agent_security.egress import analyze

        # `read_only_tools` rides on the policy, which is built once where
        # the policy is resolved (proxy startup, or first use in the SDK).
        # Reading it from admina.yaml here would put a blocking filesystem
        # read and a YAML parse inside this coroutine on every governed
        # call, breaking the "no storage, no side effects" contract above.
        tool_name = params.get("name", "") if isinstance(params, dict) else ""
        read_only_tools = getattr(egress_policy, "read_only_tools", frozenset())
        intent = analyze(params, tool_name, read_only_tools)
        decision = egress_policy.evaluate(intent, egress_mode)
        result.checks["egress"] = {
            "status": intent.status.value,
            "destinations": list(intent.destinations),
            "write_shaped": intent.write_shaped,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "evidence": dict(intent.evidence),
            "blocked": list(decision.blocked),
        }
        if not decision.allowed:
            result.action = GovernanceAction.BLOCK
            result.risk_level = decision.risk_level

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
                # The class of the exception only: its message can quote
                # the governed text (admina.core.exception_log).
                logger.error(
                    "Guard %r failed its contract and was skipped: %s",
                    guard.name,
                    type(exc).__name__,
                )
                log_frames(logger, f"Guard {guard.name!r}", exc)
                result.checks[f"guard_{guard.name}"] = {
                    "action": "ERROR",
                    "error": type(exc).__name__,
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


def unfinished_pipeline_result(
    check: dict[str, Any],
    *,
    block: bool,
    mode: str,
    request_id: str,
    latency_ms: float,
) -> GovernanceResult:
    """The result for a pipeline run that did not complete.

    *check* is stored as ``checks["pipeline"]``. With *block* the action is
    BLOCK (risk HIGH), downgraded to ALLOW with ``would_action=BLOCK`` in
    ``observe`` / ``dry-run`` *mode*, as for any decision of the pipeline.
    """
    result = GovernanceResult(checks={"pipeline": check}, mode=mode, latency_ms=latency_ms)
    if block:
        if mode in ("observe", "dry-run"):
            result.would_action = GovernanceAction.BLOCK
        else:
            result.action = GovernanceAction.BLOCK
            result.risk_level = RiskLevel.HIGH
    result.gov_response = GovResponse(
        content="null",
        action="BLOCK" if result.action == GovernanceAction.BLOCK else "ALLOW",
        risk_level="HIGH" if result.risk_level == RiskLevel.HIGH else "LOW",
        domain="pipeline",
        latency_us=latency_ms * 1000,
        request_id=request_id,
    )
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


def _has_deep_text(obj: Any, depth: int = 0) -> bool:
    """Whether *obj* holds text deeper than :data:`SCAN_DEPTH`: a string, or
    a non-empty object or array, past that level. Numbers, booleans, null
    and empty values hold none."""
    if depth > SCAN_DEPTH:
        return isinstance(obj, (str, dict, list)) and bool(obj)
    if isinstance(obj, dict):
        return any(
            _has_deep_text(k, depth + 1) or _has_deep_text(v, depth + 1) for k, v in obj.items()
        )
    if isinstance(obj, list):
        return any(_has_deep_text(item, depth + 1) for item in obj)
    return False


def _pii_accumulator() -> dict[str, Any]:
    return {"redacted_text": "", "entities": [], "count": 0}


def _redact_params(params: dict, pii_redactor: Any) -> tuple[dict, dict]:
    """Redact PII from all string values in params; keys are kept."""
    total_result = _pii_accumulator()
    redacted = _deep_redact(params, total_result, pii_redactor)
    return redacted, total_result


def redact_response_result(result: Any, pii_redactor: Any) -> tuple[Any, int]:
    """Recursively PII-redact an MCP tool result (str | dict | list).

    Returns (redacted_result, pii_count). Mirrors the request-side deep
    redaction: every string value is redacted, keys are kept.
    """
    acc = _pii_accumulator()
    redacted = _deep_redact(result, acc, pii_redactor)
    return redacted, acc["count"]


def _redact_string(text: str, result: dict, pii_redactor: Any) -> str:
    r = pii_redactor.redact(text)
    result["entities"].extend(r["entities"])
    result["count"] += r["count"]
    return r["redacted_text"]


def _deep_redact(
    obj: Any, result: dict, pii_redactor: Any, depth: int = 0, *, redact_keys: bool = False
) -> Any:
    """*obj* with every string value redacted, down to the scan depth limit.

    Dict keys are kept as they are, unless *redact_keys* is set: then they
    are redacted too, and two keys that redact to the same text are told
    apart with a numeric suffix (``[EMAIL]``, ``[EMAIL]#2``) so no value is
    dropped. Non-string keys are kept either way.
    """
    if depth > _MAX_SCAN_DEPTH:
        return obj
    if isinstance(obj, str):
        return _redact_string(obj, result, pii_redactor)
    elif isinstance(obj, dict):
        if not redact_keys:
            return {k: _deep_redact(v, result, pii_redactor, depth + 1) for k, v in obj.items()}
        out: dict = {}
        for k, v in obj.items():
            rk = _deep_redact(k, result, pii_redactor, depth + 1, redact_keys=True)
            rv = _deep_redact(v, result, pii_redactor, depth + 1, redact_keys=True)
            if isinstance(rk, str) and rk in out:
                base, suffix = rk, 2
                while f"{base}#{suffix}" in out:
                    suffix += 1
                rk = f"{base}#{suffix}"
            out[rk] = rv
        return out
    elif isinstance(obj, list):
        return [
            _deep_redact(item, result, pii_redactor, depth + 1, redact_keys=redact_keys)
            for item in obj
        ]
    return obj


# Fields of a chat message whose string value is text written by a person or
# a model. ``content`` may also be a list of parts, each a string or an object
# with a string ``text``.
_CHAT_TEXT_FIELDS = ("content", "reasoning_content", "reasoning", "refusal")


def redact_chat_params(params: dict, pii_redactor: Any) -> tuple[dict, dict]:
    """*params* (``{"messages": [...]}`` of a chat completion) with the text
    of each message redacted, and the PII result.

    Redacted: the string of each text field (``content``, reasoning and
    refusal text), the ``text`` of each content part and tool call
    ``arguments`` (``tool_calls[].function.arguments`` and
    ``function_call.arguments``). Everything else is kept as it is: keys,
    ``role``, ``name``, ``tool_call_id``, ids, image and audio parts. Items of
    ``messages`` that are not objects are kept; *params* without a list of
    messages is returned unchanged.
    """
    result = _pii_accumulator()
    messages = params.get("messages")
    if not isinstance(messages, list):
        return params, result
    redacted = [_redact_chat_message(m, result, pii_redactor) for m in messages]
    return {**params, "messages": redacted}, result


def _redact_chat_message(message: Any, result: dict, pii_redactor: Any) -> Any:
    if not isinstance(message, dict):
        return message
    out = dict(message)
    for name in _CHAT_TEXT_FIELDS:
        value = out.get(name)
        if isinstance(value, str):
            out[name] = _redact_string(value, result, pii_redactor)
        elif name == "content" and isinstance(value, list):
            out[name] = [_redact_content_part(part, result, pii_redactor) for part in value]
    tool_calls = out.get("tool_calls")
    if isinstance(tool_calls, list):
        out["tool_calls"] = [_redact_tool_call(call, result, pii_redactor) for call in tool_calls]
    function_call = out.get("function_call")
    if isinstance(function_call, dict):
        out["function_call"] = _redact_arguments(function_call, result, pii_redactor)
    return out


def _redact_content_part(part: Any, result: dict, pii_redactor: Any) -> Any:
    if isinstance(part, str):
        return _redact_string(part, result, pii_redactor)
    if isinstance(part, dict) and isinstance(part.get("text"), str):
        return {**part, "text": _redact_string(part["text"], result, pii_redactor)}
    return part


def _redact_tool_call(call: Any, result: dict, pii_redactor: Any) -> Any:
    if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
        return call
    return {**call, "function": _redact_arguments(call["function"], result, pii_redactor)}


def _redact_arguments(function: dict, result: dict, pii_redactor: Any) -> dict:
    arguments = function.get("arguments")
    if not isinstance(arguments, str):
        return function
    return {**function, "arguments": _redact_string(arguments, result, pii_redactor)}


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
    metadata: dict[str, Any] = {"similarity": loop_result.get("similarity")}
    if result.action == GovernanceAction.BLOCK:
        metadata["reason"] = _block_reason(result.checks)
    return GovResponse(
        content=json.dumps(result.redacted_body, default=str),
        action=(_action_raw.value if hasattr(_action_raw, "value") else _action_raw).upper(),
        risk_level=(_risk_raw.value if hasattr(_risk_raw, "value") else _risk_raw).upper(),
        domain=_deciding_domain,
        latency_us=result.latency_ms * 1000,
        request_id=request_id,
        metadata=metadata,
    )


def _block_reason(checks: dict[str, Any]) -> str:
    """The cause of a BLOCK, from the stage that set it: the firewall
    (``injection_detected``), text past :data:`SCAN_DEPTH`
    (``scan_depth_exceeded``), the egress policy (``egress_refused``) or a
    governance guard, by its verdict or by its failure in closed fail mode
    (``guard_blocked``). The stages run in this order and each runs only
    while the request is allowed, so the first one that blocked decides."""
    if (checks.get("firewall") or {}).get("is_injection"):
        return "injection_detected"
    if "scan_depth" in checks:
        return "scan_depth_exceeded"
    if (checks.get("egress") or {}).get("allowed") is False:
        return "egress_refused"
    if any(
        name.startswith("guard_") and (check or {}).get("action") in ("BLOCK", "REDACT", "ERROR")
        for name, check in checks.items()
    ):
        return "guard_blocked"
    return "injection_detected"

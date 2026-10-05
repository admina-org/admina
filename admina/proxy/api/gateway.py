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

"""OpenAI-compatible governance gateway.

A fifth governed surface (after /mcp, /api/v1/validate, GovernedModel,
GovernedAgent): an OpenAI-compatible HTTP API that forwards to a
configurable upstream while applying the canonical governance pipeline
inline. Any OpenAI-compatible front-end can point at Admina instead of
the upstream and get governance with no further configuration.

Routes (prefix /v1):
  POST /v1/chat/completions   — streaming (SSE) and non-streaming
  GET  /v1/models             — passthrough with optional allow-list
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from admina.core.event_bus import GovernanceEvent as BusGovernanceEvent
from admina.core.event_bus import bus as governance_bus
from admina.core.types import EventType, GovernanceAction, RiskLevel
from admina.domains.agent_security.egress import resolve_egress_mode
from admina.domains.governance import (
    build_governance_details,
    redact_response_result,
    run_pipeline,
    safe_serialize,
)
from admina.proxy.config import GovernanceEvent

logger = logging.getLogger(__name__)

# Strong references to fire-and-forget tasks, so they are not
# garbage-collected before completion (see asyncio.create_task docs).
_background_tasks: set[asyncio.Task] = set()


def _spawn(coro: Any) -> asyncio.Task:
    """Schedule *coro* as a background task and keep a strong ref."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


def _decision_metadata(gov_response: Any) -> dict:
    """Event-bus metadata for a gateway decision.

    The same fields the /mcp surface publishes, minus ``content``: the
    (redacted) request body never leaves the request on the bus, so live
    subscribers (dashboard feed, alerts, OTel) see the decision only.
    """
    meta = gov_response.to_dict()
    meta.pop("content", None)
    return meta


async def _emit_decision_safe(event: BusGovernanceEvent) -> None:
    """Emit *event* on the governance bus; a failing subscriber is logged
    and never propagates to the request."""
    try:
        await governance_bus.emit(event)
    except Exception:
        logger.warning("Gateway governance event emission failed", exc_info=True)


def _emit_decision(gov_response: Any, session_id: str) -> None:
    """Publish one GOVERNANCE_DECISION event for a gateway request,
    fire-and-forget: it adds no latency and cannot fail the request."""
    _spawn(
        _emit_decision_safe(
            BusGovernanceEvent(
                event_type=EventType.GOVERNANCE_DECISION,
                session_id=session_id,
                action=gov_response.action,
                risk_level=gov_response.risk_level,
                domain="gateway",
                metadata=_decision_metadata(gov_response),
            )
        )
    )


def _count_decision(state: Any, action: str, pii_count: int) -> None:
    """Count a governed gateway request in the proxy counters (``/api/stats``
    and ``/metrics``), as ``/mcp`` does: ``requests_total``, then
    ``requests_blocked`` for BLOCK and CIRCUIT_BREAK or ``requests_allowed``
    otherwise, and ``requests_redacted`` when PII was redacted."""
    inc = getattr(state, "inc_metric", None)
    if inc is None:
        return
    inc("requests_total")
    if action in ("BLOCK", "CIRCUIT_BREAK"):
        inc("requests_blocked")
    else:
        inc("requests_allowed")
    if pii_count > 0:
        inc("requests_redacted")


def _observe_latency(state: Any, start: float) -> None:
    """Add the time since *start* (``time.perf_counter()``) to the proxy's
    average request latency."""
    update = getattr(state, "update_avg_latency", None)
    if update is not None:
        update((time.perf_counter() - start) * 1000)


def _enum_value(enum_cls: Any, value: Any, default: Any) -> Any:
    """*value* (an enum member or its name or value, any case) as a member
    of *enum_cls*; *default* when it is none of them."""
    raw = str(getattr(value, "value", value) or "").lower()
    try:
        return enum_cls(raw)
    except ValueError:
        return default


def _analytics_event(
    pre: Any, *, event_id: str, agent_id: str, session_id: str, prompt_text: str
) -> GovernanceEvent:
    """The analytics row (ClickHouse ``governance_events``) of a gateway
    request: the same columns as an ``/mcp`` row, with event type
    ``gateway_request`` and method ``chat.completions``. Like the ``/mcp``
    row it holds the governance checks and a truncated hash of the
    prompt, never the prompt itself."""
    return GovernanceEvent(
        event_id=event_id,
        timestamp=datetime.now(UTC).isoformat(),
        event_type=EventType.GATEWAY_REQUEST,
        agent_id=agent_id,
        session_id=session_id,
        method="chat.completions",
        action=_enum_value(GovernanceAction, pre.action, GovernanceAction.ALLOW),
        risk_level=_enum_value(RiskLevel, pre.risk_level, RiskLevel.LOW),
        details=build_governance_details(pre),
        latency_ms=pre.latency_ms,
        request_hash=hashlib.sha256(prompt_text.encode()).hexdigest()[:32],
    )


async def _store_event_safe(
    store_event: Callable[[GovernanceEvent], Awaitable[None]], event: GovernanceEvent
) -> None:
    """Store *event* with *store_event*; a failure is logged and never
    reaches the request."""
    try:
        await store_event(event)
    except Exception:
        logger.warning("Gateway analytics event storage failed", exc_info=True)


def _extract_prompt_text(messages: list) -> str:
    """Concatenate the text of every chat message for governance scanning.

    Handles both string ``content`` and OpenAI vision-style content parts
    (a list of ``{"type": "text", "text": ...}`` dicts). Non-string,
    non-list content and malformed entries are skipped.
    """
    parts: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            if content:
                parts.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    parts.append(part["text"])
    return "\n".join(parts)


def _sse_format(obj: dict) -> str:
    """Serialise *obj* as a single SSE ``data:`` event (compact JSON)."""
    return f"data: {json.dumps(obj, separators=(',', ':'))}\n\n"


def _parse_sse_data(line: str) -> dict | None:
    """Parse one upstream SSE line into a dict.

    Returns None for keep-alives, the ``[DONE]`` sentinel, empty payloads,
    and any non-JSON body — callers treat None as "skip this line".
    """
    line = line.strip()
    if not line.startswith("data:"):
        return None
    payload = line[len("data:") :].strip()
    if not payload or payload == "[DONE]":
        return None
    try:
        parsed = json.loads(payload)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _delta_content(chunk: dict) -> str:
    """Return ``choices[0].delta.content`` or "" when absent/None."""
    try:
        return chunk["choices"][0]["delta"].get("content") or ""
    except (KeyError, IndexError, TypeError, AttributeError):
        return ""


def _finish_reason(chunk: dict) -> str | None:
    """Return ``choices[0].finish_reason`` or None when absent."""
    try:
        return chunk["choices"][0].get("finish_reason")
    except (KeyError, IndexError, TypeError):
        return None


def _synthetic_completion(model: str, message: str) -> dict:
    """A non-streaming OpenAI completion carrying the governance block.

    Shaped so OpenAI-compatible UIs render it as a normal (if refused)
    response instead of surfacing a raw HTTP error.
    """
    return {
        "id": f"chatcmpl-admina-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": message},
                "finish_reason": "content_filter",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _synthetic_stream(model: str, message: str) -> list[str]:
    """SSE lines for a blocked streaming request: one content_filter chunk
    then ``data: [DONE]`` — never a completion object on a streaming
    request (that would break SSE parsing on the client)."""
    chunk = {
        "id": f"chatcmpl-admina-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"role": "assistant", "content": message},
                "finish_reason": "content_filter",
            }
        ],
    }
    return [_sse_format(chunk), "data: [DONE]\n\n"]


def _content_chunk(template: dict, content: str, model: str) -> dict:
    """A content-bearing chat.completion.chunk cloned from *template*'s
    identity fields (id/created/model) with a fresh redacted delta."""
    return {
        "id": template.get("id", ""),
        "object": "chat.completion.chunk",
        "created": template.get("created", int(time.time())),
        "model": template.get("model", model),
        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}],
    }


def _finish_chunk(template: dict, reason: str, model: str) -> dict:
    """A terminal chat.completion.chunk (empty delta) preserving the
    upstream finish_reason so clients close the turn correctly."""
    return {
        "id": template.get("id", ""),
        "object": "chat.completion.chunk",
        "created": template.get("created", int(time.time())),
        "model": template.get("model", model),
        "choices": [{"index": 0, "delta": {}, "finish_reason": reason}],
    }


class _PassthroughRedactor:
    """Drop-in for StreamRedactor used when PII redaction is disabled:
    echoes each delta immediately, holds nothing, redacts nothing."""

    def feed(self, delta: str) -> list[str]:
        return [delta] if delta else []

    def finish(self) -> tuple[str, dict]:
        return "", {"pii_count": 0}


async def _aiter_list(items) -> AsyncIterator[str]:
    """Adapt a synchronous list of SSE lines to an async iterator."""
    for item in items:
        yield item


async def _governed_sse_stream(lines, redactor, model: str) -> AsyncIterator[str]:
    """Re-emit upstream SSE as governed SSE.

    Content deltas are recomposed and redacted through *redactor* (feed);
    at the upstream's finish chunk the window is flushed (finish) and the
    trailing redacted tail is emitted before the terminal finish marker.
    The stream always ends with ``data: [DONE]``. Role-only and empty
    deltas are dropped; identity fields (id/created/model) are preserved.
    """
    flushed = False
    async for raw in lines:
        stripped = (raw or "").strip()
        if not stripped or stripped == "data: [DONE]":
            continue
        chunk = _parse_sse_data(stripped)
        if chunk is None:
            continue
        content = _delta_content(chunk)
        if content:
            for safe in redactor.feed(content):
                if safe:
                    yield _sse_format(_content_chunk(chunk, safe, model))
        reason = _finish_reason(chunk)
        if reason is not None and not flushed:
            tail, _summary = redactor.finish()
            flushed = True
            if tail:
                yield _sse_format(_content_chunk(chunk, tail, model))
            yield _sse_format(_finish_chunk(chunk, reason, model))
    if not flushed:
        tail, _summary = redactor.finish()
        if tail:
            yield _sse_format(_content_chunk({}, tail, model))
    yield "data: [DONE]\n\n"


async def _record_forensic(
    forensic_box: Any,
    *,
    event_id: str,
    agent_id: str,
    session_id: str,
    action: str,
    risk_level: str,
    pre: Any,
) -> None:
    """Record the gateway request to the forensic log — the fifth surface
    on the canonical pipeline. Runs off the event loop like /mcp does."""
    if forensic_box is None:
        return
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        lambda: forensic_box.record(
            {
                "event_id": event_id,
                "event_type": EventType.GATEWAY_REQUEST,
                "agent_id": agent_id,
                "session_id": session_id,
                "method": "chat.completions",
                "action": action,
                "risk_level": risk_level,
                "governance_latency_ms": round(pre.latency_ms, 2),
                "checks": {k: safe_serialize(v) for k, v in pre.checks.items()},
            }
        ),
    )


def create_gateway_endpoints(
    *,
    get_state: Any,
    get_settings: Any,
    store_event: Callable[[GovernanceEvent], Awaitable[None]] | None = None,
) -> APIRouter:
    """Create the OpenAI-compatible gateway router (prefix ``/v1``).

    A fresh router is created on each call for test isolation, mirroring
    :func:`admina.proxy.api.integration.create_integration_endpoints`.

    Args:
        get_state: Callable returning the ProxyState (firewall, pii_redactor,
            loop_breaker, egress_policy, governance_guards, forensic_box,
            http_client).
        get_settings: Callable returning the settings object.
        store_event: Coroutine function storing a :class:`GovernanceEvent`
            in the analytics store; called, fire-and-forget, for every
            governed request while the state has a ``clickhouse`` client.
    """
    router = APIRouter(prefix="/v1", tags=["gateway"])

    @router.get("/models", summary="List models (passthrough with optional allow-list)")
    async def list_models() -> JSONResponse:
        state = get_state()
        cfg = get_settings()
        url = f"{cfg.ADMINA_GATEWAY_UPSTREAM.rstrip('/')}/models"
        try:
            resp = await state.http_client.get(url)
        except httpx.ConnectError:
            raise HTTPException(status_code=502, detail="Gateway upstream unreachable")
        data = resp.json()
        allow = [m.strip() for m in cfg.ADMINA_GATEWAY_MODELS_ALLOWLIST.split(",") if m.strip()]
        if allow and isinstance(data.get("data"), list):
            data["data"] = [m for m in data["data"] if m.get("id") in allow]
        return JSONResponse(content=data, status_code=resp.status_code)

    @router.post("/chat/completions", summary="Governed OpenAI chat completions")
    async def chat_completions(request: Request):
        state = get_state()
        cfg = get_settings()
        try:
            body = await request.json()
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        messages = body.get("messages") or []
        model = body.get("model", "unknown")
        stream = bool(body.get("stream", False))
        session_id = re.sub(r"[\r\n]", "", request.headers.get("X-Session-Id", "default"))[:128]
        agent_id = re.sub(r"[\r\n]", "", request.headers.get("X-Agent-Id", "gateway"))[:128]
        prompt_text = _extract_prompt_text(messages)
        event_id = uuid.uuid4().hex
        start = time.perf_counter()

        pre = await run_pipeline(
            body={"params": {"messages": messages}},
            content_str=prompt_text,
            session_id=session_id,
            agent_id=agent_id,
            request_id=event_id,
            params={"messages": messages},
            firewall=state.firewall,
            pii_redactor=state.pii_redactor,
            loop_breaker=state.loop_breaker,
            governance_guards=state.governance_guards,
            injection_enabled=cfg.INJECTION_FAST_PATH_ENABLED,
            pii_enabled=cfg.PII_REDACTION_ENABLED,
            loop_enabled=False,
            mode=cfg.GOVERNANCE_MODE,
            guard_fail_mode=cfg.GUARD_FAIL_MODE,
            egress_policy=state.egress_policy,
            egress_mode=resolve_egress_mode(cfg.GOVERNANCE_MODE),
        )
        action = pre.gov_response.action  # uppercase: ALLOW/BLOCK/CIRCUIT_BREAK
        pii_count = pre.checks.get("pii_redaction", {}).get("count", 0)
        _count_decision(state, action, pii_count)

        await _record_forensic(
            state.forensic_box,
            event_id=event_id,
            agent_id=agent_id,
            session_id=session_id,
            action=action,
            risk_level=pre.gov_response.risk_level,
            pre=pre,
        )
        if store_event is not None and getattr(state, "clickhouse", None):
            _spawn(
                _store_event_safe(
                    store_event,
                    _analytics_event(
                        pre,
                        event_id=event_id,
                        agent_id=agent_id,
                        session_id=session_id,
                        prompt_text=prompt_text,
                    ),
                )
            )

        block_message = cfg.ADMINA_GATEWAY_BLOCK_MESSAGE
        if action in ("BLOCK", "CIRCUIT_BREAK"):
            _emit_decision(pre.gov_response, session_id)
            _observe_latency(state, start)
            if stream:
                return StreamingResponse(
                    _aiter_list(_synthetic_stream(model, block_message)),
                    media_type="text/event-stream",
                )
            return JSONResponse(content=_synthetic_completion(model, block_message))

        upstream = cfg.ADMINA_GATEWAY_UPSTREAM.rstrip("/")
        url = f"{upstream}/chat/completions"
        headers = {"X-Admina-Event-Id": event_id}

        fwd_messages = pre.redacted_body["params"]["messages"] if pii_count > 0 else messages
        forward_body = {**body, "messages": fwd_messages}

        if stream:
            forward_body["stream"] = True

            if cfg.PII_REDACTION_ENABLED:
                from admina.sdk.streaming import StreamRedactor

                redactor = StreamRedactor(state.pii_redactor)
            else:
                redactor = _PassthroughRedactor()

            # Open the upstream connection eagerly, before the
            # StreamingResponse is constructed. Once the response is
            # returned, Starlette sends the HTTP status line before pulling
            # the first chunk from the body generator — so a ConnectError
            # raised from *inside* the generator can no longer become a
            # clean 502 (the 200 has already gone out). Entering the
            # context manager here, synchronously, keeps the connect-time
            # failure catchable, mirroring the non-streaming path below.
            stream_cm = state.http_client.stream("POST", url, json=forward_body, headers=headers)
            try:
                upstream_resp = await stream_cm.__aenter__()
            except httpx.ConnectError:
                _emit_decision(pre.gov_response, session_id)
                raise HTTPException(status_code=502, detail="Gateway upstream unreachable")

            async def _proxy() -> AsyncIterator[str]:
                try:
                    async for sse in _governed_sse_stream(
                        upstream_resp.aiter_lines(), redactor, model
                    ):
                        yield sse
                finally:
                    # One decision event per stream, at completion (or
                    # client disconnect), never per chunk.
                    _emit_decision(pre.gov_response, session_id)
                    _observe_latency(state, start)
                    await stream_cm.__aexit__(None, None, None)

            return StreamingResponse(_proxy(), media_type="text/event-stream")

        # non-streaming passthrough
        _emit_decision(pre.gov_response, session_id)
        try:
            resp = await state.http_client.post(url, json=forward_body, headers=headers)
        except httpx.ConnectError:
            raise HTTPException(status_code=502, detail="Gateway upstream unreachable")
        finally:
            _observe_latency(state, start)
        data = resp.json()
        if cfg.PII_REDACTION_ENABLED and isinstance(data.get("choices"), list):
            data["choices"], _ = redact_response_result(data["choices"], state.pii_redactor)
        return JSONResponse(content=data, status_code=resp.status_code)

    return router

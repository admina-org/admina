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
  GET  /v1/admina/ruleset     — the active firewall ruleset

Every chat completion response carries ``X-Admina-Ruleset``, the
:func:`~admina.domains.agent_security.ruleset.ruleset_sha256` of the rules
the gateway scans with (see :mod:`admina.proxy.gateway_scan`). The firewall
scans the messages of the roles in ``ADMINA_GATEWAY_SCAN_ROLES``, narrowed
by an accepted ``X-Admina-Scan-Policy`` (see
:mod:`admina.domains.agent_security.scan_policy`).

The governance pipeline runs in the worker threads of
:mod:`admina.proxy.pipeline_executor`, within the time budget
``ADMINA_GATEWAY_PIPELINE_TIMEOUT``: a request whose decision takes longer
is blocked, in every governance mode. An exception inside the pipeline
follows ``ADMINA_GUARD_FAIL_MODE``: ``open`` lets the request through,
``closed`` blocks it. Both outcomes are recorded as ``checks["pipeline"]``.

Both forward to the upstream route named by the ``X-Admina-Upstream``
request header, or to the default route without it (see
:mod:`admina.proxy.gateway_upstreams`). An unknown route name is answered
with 400 before anything else happens. The upstream receives the route's
own API key, if any, never the caller's credentials or headers.

Upstream responses (stream mode, timeouts and connection pool: see
:mod:`admina.proxy.gateway_transport`):

- An upstream error (non-2xx) reaches the client with its status, body and
  content type, streaming or not.
- Without a response transformation (PII redaction off) a JSON body is
  forwarded unchanged, and so is a stream in ``passthrough`` mode, each SSE
  event as soon as it is complete. Otherwise each SSE chunk is parsed and
  re-serialised (``governed``).
- A timeout before the response starts gets 504, any other transport
  failure 502, with an OpenAI-style error body. A failure during a stream
  ends it with one ``data: {"error": ...}`` event and no ``data: [DONE]``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from collections.abc import AsyncIterator, Callable, Coroutine
from functools import cache
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from admina import __version__
from admina.core.types import EventType
from admina.domains.agent_security.egress import resolve_egress_mode
from admina.domains.agent_security.scan_policy import (
    SCAN_POLICY_HEADER,
    SCAN_ROLES,
    ScanScope,
    parse_scan_roles,
    resolve_scan_scope,
    scope_texts,
)
from admina.domains.governance import (
    GovernanceResult,
    run_pipeline,
    safe_serialize,
    unfinished_pipeline_result,
)
from admina.proxy.gateway_scan import (
    RULESET_HEADER,
    GatewayScanConfig,
    default_gateway_scan_config,
)
from admina.proxy.gateway_transport import DEFAULT_STREAM_MODE, total_deadline
from admina.proxy.gateway_upstreams import UPSTREAM_HEADER, GatewayUpstream, GatewayUpstreams
from admina.proxy.pipeline_executor import PipelineExecutor, PipelineTimeout

logger = logging.getLogger("admina.proxy.gateway")

# Longest X-Admina-Upstream value considered, as for X-Session-Id.
_ROUTE_HEADER_MAX = 128


def _requested_route(value: str) -> str:
    """Route name from an ``X-Admina-Upstream`` value: CR/LF removed,
    surrounding whitespace trimmed, at most 128 characters kept."""
    return re.sub(r"[\r\n]", "", value).strip()[:_ROUTE_HEADER_MAX]


def _select_upstream(request: Request, state: Any, cfg: Any) -> GatewayUpstream | None:
    """The route the request asks for, or None when no route has that name.

    Routes are resolved at startup into ``state.gateway_upstreams``; a
    router used without them has one route to ``ADMINA_GATEWAY_UPSTREAM``,
    without a key.
    """
    upstreams = getattr(state, "gateway_upstreams", None) or GatewayUpstreams.single(
        cfg.ADMINA_GATEWAY_UPSTREAM
    )
    return upstreams.select(_requested_route(request.headers.get(UPSTREAM_HEADER, "")))


def _scan_config(state: Any) -> GatewayScanConfig:
    """The scan settings resolved at startup, or the defaults for a router
    used without them."""
    return getattr(state, "gateway_scan", None) or default_gateway_scan_config()


def _scan_scope(request: Request, state: Any, cfg: Any, scan: GatewayScanConfig) -> ScanScope:
    """The scan scope of *request*; a scan policy is counted by outcome."""
    scope = resolve_scan_scope(
        request.headers.getlist(SCAN_POLICY_HEADER),
        scan_roles=parse_scan_roles(cfg.ADMINA_GATEWAY_SCAN_ROLES),
        prescan_tags=scan.prescan_tags,
        accepted_rulesets=scan.accepted_rulesets,
    )
    inc_metric = getattr(state, "inc_metric", None)
    if scope.status != "none" and inc_metric is not None:
        inc_metric(f"prescan_{scope.status}")
    return scope


@cache
def _default_executor() -> PipelineExecutor:
    return PipelineExecutor()


async def _govern(
    state: Any,
    cfg: Any,
    pipeline: Callable[[], Coroutine[Any, Any, GovernanceResult]],
    request_id: str,
) -> GovernanceResult:
    """The result of *pipeline*, run in the worker threads (those built at
    startup, or a default pool) within the time budget."""
    executor = getattr(state, "pipeline_executor", None) or _default_executor()
    budget = cfg.ADMINA_GATEWAY_PIPELINE_TIMEOUT
    started = time.perf_counter()
    try:
        return await executor.run_coroutine(pipeline, timeout=budget)
    except PipelineTimeout:
        logger.warning("Gateway governance exceeded its time budget (%g s): blocked", budget)
        check: dict[str, Any] = {
            "action": "BLOCK",
            "reason": "time_budget_exceeded",
            "budget_ms": round(budget * 1000),
        }
        block, mode = True, "enforce"  # the budget blocks in every governance mode
    except Exception as exc:  # noqa: BLE001 — any failure is a governance decision
        logger.error("Gateway governance pipeline failed: %s", type(exc).__name__)
        logger.debug("Gateway governance pipeline failure", exc_info=True)
        check = {"action": "ERROR", "error": type(exc).__name__}
        block, mode = cfg.GUARD_FAIL_MODE == "closed", cfg.GOVERNANCE_MODE
    return unfinished_pipeline_result(
        check,
        block=block,
        mode=mode,
        request_id=request_id,
        latency_ms=(time.perf_counter() - started) * 1000,
    )


def _error(message: str, error_type: str, code: str) -> dict:
    """The ``error`` object of an error body in the OpenAI format."""
    return {"message": message, "type": error_type, "param": None, "code": code}


def _error_response(status: int, error: dict) -> JSONResponse:
    """An error response in the OpenAI format: ``{"error": {...}}``."""
    return JSONResponse(status_code=status, content={"error": error})


def _unknown_upstream() -> JSONResponse:
    """400 in the OpenAI error format for an unknown route name."""
    return _error_response(
        400,
        _error(
            f"Unknown upstream route in the {UPSTREAM_HEADER} header.",
            "invalid_request_error",
            "unknown_upstream",
        ),
    )


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


async def _aiter_list(items) -> AsyncIterator[str]:
    """Adapt a synchronous list of SSE lines to an async iterator."""
    for item in items:
        yield item


# Keys whose scalar values name or classify a part of a completion instead
# of carrying generated text: kept as they are while redacting.
_STRUCTURAL_KEYS = frozenset({"index", "id", "type", "role", "name", "finish_reason"})
# Choice fields that carry generated text as tokens (token texts, bytes,
# token ids), which cannot be redacted one token at a time: sent as null
# while redacting.
_TOKEN_FIELDS = ("logprobs", "token_ids")
# Chunk identity, copied onto the chunk that carries text held back until
# the end of the stream.
_CHUNK_IDENTITY_FIELDS = ("id", "object", "created", "model", "system_fingerprint")
# Fields outside the choices kept as they are while redacting (when scalar).
_COMPLETION_KEPT_FIELDS = frozenset({*_CHUNK_IDENTITY_FIELDS, "service_tier"})
# Deepest nesting followed while redacting; deeper values are dropped.
_MAX_REDACT_DEPTH = 16


def _as_index(value: Any, default: int) -> int:
    """An ``index`` field, or *default* when it is missing or not an integer."""
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _is_scalar(value: Any) -> bool:
    return not isinstance(value, (dict, list))


def _kept(key: Any, value: Any) -> bool:
    """True for the scalar value of a structural key."""
    return key in _STRUCTURAL_KEYS and _is_scalar(value)


def _item_step(item: Any, pos: int) -> tuple[str, int]:
    """Path step of a list item: its integer ``index`` when it has one (tool
    calls, for instance), else its position in the list."""
    index = item.get("index") if isinstance(item, dict) else None
    if isinstance(index, int) and not isinstance(index, bool):
        return ("index", index)
    return ("position", pos)


def _redact_values(value: Any, pii: Any, depth: int = 0) -> Any:
    """*value* with every string redacted as a whole, at any depth.

    Keys and the scalar values of structural keys are kept; values nested
    deeper than the depth limit are dropped (None).
    """
    if depth > _MAX_REDACT_DEPTH:
        return None
    if isinstance(value, str):
        return pii.redact(value)["redacted_text"]
    if isinstance(value, dict):
        return {
            k: v if _kept(k, v) else _redact_values(v, pii, depth + 1) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_values(item, pii, depth + 1) for item in value]
    return value


def _without_tokens(choice: Any) -> Any:
    """*choice* with ``logprobs`` and ``token_ids`` null (when present)."""
    if not isinstance(choice, dict):
        return choice
    return {**choice, **{field: None for field in _TOKEN_FIELDS if field in choice}}


def _redacted_completion(data: dict, pii: Any) -> dict:
    """A non-streaming completion with every string redacted as a whole
    value, except structural values and the completion's identity, and
    with ``logprobs`` and ``token_ids`` of each choice null."""
    out: dict = {}
    for key, value in data.items():
        if key in _COMPLETION_KEPT_FIELDS and _is_scalar(value):
            out[key] = value
        elif key == "choices" and isinstance(value, list):
            out[key] = [_redact_values(_without_tokens(c), pii, 1) for c in value]
        else:
            out[key] = _redact_values(value, pii)
    return out


class _StreamedText:
    """Redacts every string that streamed completion chunks carry.

    Each chunk is rebuilt with all of its fields and keys. Inside a choice,
    every string goes through one window of a windowed
    :class:`~admina.sdk.streaming.StreamRedactor` per choice and path (a
    list item's path uses its integer ``index``, or else its position), so
    an entity split across chunks is redacted before any of it is sent:
    the delta's ``content`` (a string or a list of parts), reasoning text,
    tool and function call ``arguments`` and any other field. The text a
    window holds back is released with the finish chunk of its choice, at
    the same path, or by :meth:`remainder` at the end of the stream.

    Kept as they are: the scalar values of structural keys (``index``,
    ``id``, ``type``, ``role``, ``name``, ``finish_reason``) and the chunk
    identity. Sent as ``null``: ``logprobs`` and ``token_ids``. Other
    strings outside the choices, and comment lines, are redacted as whole
    values. Values nested deeper than the depth limit are dropped. Without
    a PII redactor, chunks and comments pass unchanged.
    """

    def __init__(self, pii_redactor: Any = None) -> None:
        self._pii = pii_redactor
        self._windows: dict[tuple, Any] = {}
        # "type" of the last list item seen at each item path.
        self._item_types: dict[tuple, str | None] = {}
        self._identity: dict[str, Any] = {}

    def chunk(self, chunk: dict) -> dict:
        """*chunk* with its text redacted."""
        if self._pii is None:
            return chunk
        out: dict = {}
        for key, value in chunk.items():
            if key == "choices" and isinstance(value, list):
                out[key] = [self._choice(pos, choice) for pos, choice in enumerate(value)]
            elif key in _COMPLETION_KEPT_FIELDS and _is_scalar(value):
                out[key] = value
            else:
                out[key] = _redact_values(value, self._pii)
        identity = {k: out[k] for k in _CHUNK_IDENTITY_FIELDS if k in out}
        if identity:
            self._identity = identity
        return out

    def comment(self, line: str) -> str:
        """An SSE comment line, redacted."""
        return line if self._pii is None else self._pii.redact(line)["redacted_text"]

    def remainder(self) -> dict | None:
        """A last chunk with the text still held back, or None."""
        choices = []
        for index in sorted({key[0] for key in self._windows}):
            empty = {"index": index, "delta": {}, "finish_reason": None}
            choice = self._release(index, empty)
            if choice is not None:
                choices.append(choice)
        return {**self._identity, "choices": choices} if choices else None

    def _choice(self, pos: int, choice: Any) -> Any:
        if not isinstance(choice, dict):
            return _redact_values(choice, self._pii)
        index = _as_index(choice.get("index"), pos)
        out: dict = {}
        for key, value in choice.items():
            if key in _TOKEN_FIELDS:
                out[key] = None
            elif _kept(key, value):
                out[key] = value
            else:
                out[key] = self._windowed((index, key), value, 1)
        if choice.get("finish_reason") is not None:
            released = self._release(index, out)
            if released is not None:
                out = released
        return out

    def _windowed(self, key: tuple, value: Any, depth: int) -> Any:
        """*value* with each string sent through the window of its path."""
        if depth > _MAX_REDACT_DEPTH:
            return None
        if isinstance(value, str):
            return self._feed(key, value)
        if isinstance(value, dict):
            return {
                k: v if _kept(k, v) else self._windowed((*key, k), v, depth + 1)
                for k, v in value.items()
            }
        if isinstance(value, list):
            items = []
            for pos, item in enumerate(value):
                item_key = (*key, _item_step(item, pos))
                item_type = item.get("type") if isinstance(item, dict) else None
                self._item_types[item_key] = item_type if isinstance(item_type, str) else None
                items.append(self._windowed(item_key, item, depth + 1))
            return items
        return value

    def _feed(self, key: tuple, text: str) -> str:
        window = self._windows.get(key)
        if window is None:
            from admina.sdk.streaming import StreamRedactor

            window = self._windows[key] = StreamRedactor(self._pii)
        return "".join(window.feed(text))

    def _release(self, index: int, choice: dict) -> dict | None:
        """A copy of *choice* with the text held back for choice *index*
        appended at its paths, or None when nothing was held back."""
        out: Any = choice
        released = False
        for key in [k for k in self._windows if k[0] == index]:
            tail, _summary = self._windows.pop(key).finish()
            if tail:
                out = self._with_tail(out, key, 1, tail)
                released = True
        return out if released else None

    def _with_tail(self, node: Any, key: tuple, depth: int, tail: str) -> Any:
        """A copy of *node* with *tail* appended to the string at path
        ``key[depth:]``, creating the containers that are missing."""
        if depth == len(key):
            return _text(node) + tail
        step = key[depth]
        if isinstance(step, str):
            out = dict(node) if isinstance(node, dict) else {}
            out[step] = self._with_tail(out.get(step), key, depth + 1, tail)
            return out
        items = list(node) if isinstance(node, list) else []
        for pos, item in enumerate(items):
            if _item_step(item, pos) == step:
                items[pos] = self._with_tail(item, key, depth + 1, tail)
                return items
        items.append(self._with_tail(self._new_item(key[: depth + 1]), key, depth + 1, tail))
        return items

    def _new_item(self, item_key: tuple) -> dict:
        """A list item to carry held-back text: its ``index`` (for an item
        identified by it) and the ``type`` of the last item seen there."""
        kind, number = item_key[-1]
        item: dict = {"index": number} if kind == "index" else {}
        item_type = self._item_types.get(item_key)
        if item_type is not None:
            item["type"] = item_type
        return item


async def _governed_sse_stream(
    lines: AsyncIterator[str], pii_redactor: Any = None
) -> AsyncIterator[str]:
    """Re-emit upstream SSE lines as governed SSE, one chunk per chunk.

    Each ``data:`` chunk is parsed, its text redacted through
    :class:`_StreamedText` (unchanged when *pii_redactor* is None) and
    re-serialised. Comment lines (keep-alives) are forwarded, redacted too;
    data that is not a JSON object is dropped. ``data: [DONE]`` is forwarded when the
    upstream sends it, after a chunk with any text still held back; a
    stream that ends without it gets only that chunk.
    """
    text = _StreamedText(pii_redactor)
    async for line in lines:
        if line.startswith(":"):
            yield f"{text.comment(line.rstrip())}\n\n"
            continue
        if not line.startswith("data:"):
            continue
        if line[len("data:") :].strip() == "[DONE]":
            last = text.remainder()
            if last is not None:
                yield _sse_format(last)
            yield "data: [DONE]\n\n"
            continue
        chunk = _parse_sse_data(line)
        if chunk is not None:
            yield _sse_format(text.chunk(chunk))
    last = text.remainder()
    if last is not None:
        yield _sse_format(last)


async def _record_forensic(
    forensic_box: Any,
    *,
    event_id: str,
    agent_id: str,
    session_id: str,
    upstream: str,
    action: str,
    risk_level: str,
    pre: Any,
    prescan: dict,
) -> None:
    """Record the gateway request to the forensic log — the fifth surface
    on the canonical pipeline. Runs off the event loop like /mcp does.

    *prescan* is the scan scope (:meth:`ScanScope.record`)."""
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
                "upstream": upstream,
                "action": action,
                "risk_level": risk_level,
                "governance_latency_ms": round(pre.latency_ms, 2),
                "checks": {k: safe_serialize(v) for k, v in pre.checks.items()},
                "prescan": prescan,
            }
        ),
    )


# ── Upstream exchange ────────────────────────────────────────

# Error bodies (OpenAI format) for failures the gateway answers itself. They
# never carry the exception text, which can name hosts and ports.
_UPSTREAM_TIMEOUT = _error(
    "The upstream did not respond in time.", "upstream_error", "upstream_timeout"
)
_UPSTREAM_FAILED = _error("The upstream connection failed.", "upstream_error", "upstream_error")
_UPSTREAM_INVALID = _error(
    "The upstream response could not be read.", "upstream_error", "upstream_invalid_response"
)

# End of an SSE event: a blank line, with any of the three line endings.
_EVENT_ENDS = (b"\n\n", b"\r\r", b"\r\n\r\n")


def _failure(route: GatewayUpstream, exc: Exception) -> tuple[int, dict]:
    """Status and error body for a failed upstream exchange: 504 for a
    timeout (httpx or the total deadline), 502 for any other failure."""
    logger.warning("Gateway upstream %r failed: %s", route.name, type(exc).__name__)
    if isinstance(exc, (TimeoutError, httpx.TimeoutException)):
        return 504, _UPSTREAM_TIMEOUT
    return 502, _UPSTREAM_FAILED


def _failure_response(route: GatewayUpstream, exc: Exception) -> JSONResponse:
    return _error_response(*_failure(route, exc))


def _is_success(status: int) -> bool:
    return 200 <= status < 300


def _transforms_response(cfg: Any) -> bool:
    """True when the gateway rewrites upstream responses (PII redaction)."""
    return bool(cfg.PII_REDACTION_ENABLED)


def _as_received(status: int, headers: Any, content: bytes) -> Response:
    """The upstream response as received: status, body and content type."""
    content_type = headers.get("content-type")
    return Response(
        content=content,
        status_code=status,
        headers={"content-type": content_type} if content_type else None,
    )


def _json_object(content: bytes) -> dict | None:
    """*content* parsed as a JSON object, or None."""
    try:
        data = json.loads(content)
    except ValueError:  # includes JSONDecodeError and UnicodeDecodeError
        return None
    return data if isinstance(data, dict) else None


def _event_end(buf: bytearray, start: int) -> int:
    """Offset just past the last blank line in *buf* at or after *start*;
    0 when there is none."""
    end = 0
    for sep in _EVENT_ENDS:
        at = buf.rfind(sep, start)
        if at >= 0:
            end = max(end, at + len(sep))
    return end


async def _sse_events(chunks: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """Upstream bytes, unchanged, cut at SSE event boundaries.

    Complete events are yielded as soon as their blank line arrives; bytes
    after the last boundary wait for the next read. Whatever is left when
    the body ends is yielded as it is.
    """
    pending = bytearray()
    async for chunk in chunks:
        if not chunk:
            continue
        # A boundary can straddle two reads: look back 3 bytes.
        start = max(len(pending) - 3, 0)
        pending += chunk
        end = _event_end(pending, start)
        if end:
            yield bytes(pending[:end])
            del pending[:end]
    if pending:
        yield bytes(pending)


async def _relay(
    chunks: AsyncIterator[Any],
    stream_cm: Any,
    deadline: float | None,
    route: GatewayUpstream,
) -> AsyncIterator[Any]:
    """Send *chunks* on as they come, within the total *deadline*.

    An upstream failure ends the stream with one ``data: {"error": ...}``
    event and no ``data: [DONE]``. The upstream response is closed in every
    case, also when the client goes away.
    """
    try:
        iterator = aiter(chunks)
        while True:
            try:
                async with asyncio.timeout_at(deadline):
                    chunk = await anext(iterator)
            except StopAsyncIteration:
                return
            except (TimeoutError, httpx.RequestError) as exc:
                _status, error = _failure(route, exc)
                yield _sse_format({"error": error})
                return
            yield chunk
    finally:
        await stream_cm.__aexit__(None, None, None)


async def _chat_completion(
    request: Request, state: Any, cfg: Any, scan: GatewayScanConfig
) -> Response:
    """Govern one chat completion and relay it upstream (the route handler
    adds the ruleset header)."""
    route = _select_upstream(request, state, cfg)
    if route is None:
        return _unknown_upstream()
    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})

    messages = body.get("messages") or []
    model = body.get("model", "unknown")
    stream = bool(body.get("stream", False))
    session_id = re.sub(r"[\r\n]", "", request.headers.get("X-Session-Id", "default"))[:128]
    agent_id = re.sub(r"[\r\n]", "", request.headers.get("X-Agent-Id", "gateway"))[:128]
    prompt_text = _extract_prompt_text(messages)
    if 0 < cfg.ADMINA_GATEWAY_MAX_PROMPT_CHARS < len(prompt_text):
        return _error_response(
            413,
            _error(
                "The message text exceeds the length limit.",
                "invalid_request_error",
                "prompt_too_long",
            ),
        )
    event_id = uuid.uuid4().hex
    scope = _scan_scope(request, state, cfg, scan)

    def pipeline() -> Coroutine[Any, Any, GovernanceResult]:
        # Called in a worker thread: selecting the texts to scan runs there too.
        return run_pipeline(
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
            scan_texts=scope_texts(messages, scope),
        )

    pre = await _govern(state, cfg, pipeline, event_id)
    action = pre.gov_response.action  # uppercase: ALLOW/BLOCK/CIRCUIT_BREAK

    await _record_forensic(
        state.forensic_box,
        event_id=event_id,
        agent_id=agent_id,
        session_id=session_id,
        upstream=route.name,
        action=action,
        risk_level=pre.gov_response.risk_level,
        pre=pre,
        prescan=scope.record(),
    )

    block_message = cfg.ADMINA_GATEWAY_BLOCK_MESSAGE
    if action in ("BLOCK", "CIRCUIT_BREAK"):
        if stream:
            return StreamingResponse(
                _aiter_list(_synthetic_stream(model, block_message)),
                media_type="text/event-stream",
            )
        return JSONResponse(content=_synthetic_completion(model, block_message))

    url = f"{route.url}/chat/completions"
    headers = {"X-Admina-Event-Id": event_id, **route.auth_headers()}

    pii_count = pre.checks.get("pii_redaction", {}).get("count", 0)
    fwd_messages = pre.redacted_body["params"]["messages"] if pii_count > 0 else messages
    forward_body = {**body, "messages": fwd_messages}
    client = state.gateway_http_client
    deadline = total_deadline(cfg)

    if stream:
        forward_body["stream"] = True

        # Open the upstream response here, before the StreamingResponse
        # exists: until the upstream has answered, a failure can still
        # get a status of its own (504/502), and an upstream error keeps
        # its status and body.
        stream_cm = client.stream("POST", url, json=forward_body, headers=headers)
        try:
            async with asyncio.timeout_at(deadline):
                upstream = await stream_cm.__aenter__()
        except (TimeoutError, httpx.RequestError) as exc:
            return _failure_response(route, exc)

        if not _is_success(upstream.status_code):
            try:
                async with asyncio.timeout_at(deadline):
                    content = await upstream.aread()
            except (TimeoutError, httpx.RequestError) as exc:
                return _failure_response(route, exc)
            finally:
                await stream_cm.__aexit__(None, None, None)
            return _as_received(upstream.status_code, upstream.headers, content)

        passthrough = getattr(
            state, "gateway_stream_mode", DEFAULT_STREAM_MODE
        ) == "passthrough" and not _transforms_response(cfg)
        if passthrough:
            chunks: AsyncIterator[Any] = _sse_events(upstream.aiter_bytes())
            content_type = upstream.headers.get("content-type") or "text/event-stream"
        else:
            pii = state.pii_redactor if cfg.PII_REDACTION_ENABLED else None
            chunks = _governed_sse_stream(upstream.aiter_lines(), pii)
            content_type = "text/event-stream"
        return StreamingResponse(
            _relay(chunks, stream_cm, deadline, route),
            status_code=upstream.status_code,
            headers={"content-type": content_type},
        )

    try:
        async with asyncio.timeout_at(deadline):
            resp = await client.post(url, json=forward_body, headers=headers)
    except (TimeoutError, httpx.RequestError) as exc:
        return _failure_response(route, exc)
    if not (_transforms_response(cfg) and _is_success(resp.status_code)):
        return _as_received(resp.status_code, resp.headers, resp.content)
    data = _json_object(resp.content)
    if data is None:
        return _error_response(502, _UPSTREAM_INVALID)
    return JSONResponse(
        content=_redacted_completion(data, state.pii_redactor), status_code=resp.status_code
    )


def create_gateway_endpoints(
    *,
    get_state: Any,
    get_settings: Any,
) -> APIRouter:
    """Create the OpenAI-compatible gateway router (prefix ``/v1``).

    A fresh router is created on each call for test isolation, mirroring
    :func:`admina.proxy.api.integration.create_integration_endpoints`.

    Args:
        get_state: Callable returning the ProxyState (firewall, pii_redactor,
            loop_breaker, egress_policy, governance_guards, forensic_box,
            gateway_http_client, gateway_upstreams, gateway_stream_mode,
            gateway_scan).
        get_settings: Callable returning the settings object.
    """
    router = APIRouter(prefix="/v1", tags=["gateway"])

    @router.get("/models", summary="List models (passthrough with optional allow-list)")
    async def list_models(request: Request) -> Response:
        state = get_state()
        cfg = get_settings()
        route = _select_upstream(request, state, cfg)
        if route is None:
            return _unknown_upstream()
        try:
            async with asyncio.timeout_at(total_deadline(cfg)):
                resp = await state.gateway_http_client.get(
                    f"{route.url}/models", headers=route.auth_headers()
                )
        except (TimeoutError, httpx.RequestError) as exc:
            return _failure_response(route, exc)
        allow = [m.strip() for m in cfg.ADMINA_GATEWAY_MODELS_ALLOWLIST.split(",") if m.strip()]
        if not allow or not _is_success(resp.status_code):
            return _as_received(resp.status_code, resp.headers, resp.content)
        data = _json_object(resp.content)
        if data is None:
            return _error_response(502, _UPSTREAM_INVALID)
        if isinstance(data.get("data"), list):
            data["data"] = [m for m in data["data"] if isinstance(m, dict) and m.get("id") in allow]
        return JSONResponse(content=data, status_code=resp.status_code)

    @router.post("/chat/completions", summary="Governed OpenAI chat completions")
    async def chat_completions(request: Request) -> Response:
        state = get_state()
        scan = _scan_config(state)
        response = await _chat_completion(request, state, get_settings(), scan)
        response.headers[RULESET_HEADER] = scan.ruleset_sha256
        return response

    @router.get("/admina/ruleset", summary="Active firewall ruleset")
    async def active_ruleset() -> dict[str, Any]:
        scan = _scan_config(get_state())
        roles = parse_scan_roles(get_settings().ADMINA_GATEWAY_SCAN_ROLES)
        return {
            "ruleset_sha256": scan.ruleset_sha256,
            "engine": scan.engine,
            "admina_core_version": scan.admina_core_version,
            "admina_version": __version__,
            "accepted_prescan_rulesets": list(scan.accepted_rulesets),
            "prescan_tags": sorted(scan.prescan_tags),
            "scan_roles": [role for role in SCAN_ROLES if role in roles],
        }

    return router

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
from collections.abc import AsyncIterator
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from admina.core.types import EventType
from admina.domains.agent_security.egress import resolve_egress_mode
from admina.domains.governance import redact_response_result, run_pipeline, safe_serialize
from admina.proxy.gateway_transport import DEFAULT_STREAM_MODE, total_deadline
from admina.proxy.gateway_upstreams import UPSTREAM_HEADER, GatewayUpstream, GatewayUpstreams

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


# Generated text in a streamed delta, besides tool and function call
# arguments: what the governed path redacts.
_DELTA_TEXT_FIELDS = ("content", "reasoning_content", "reasoning", "refusal")
# Chunk identity, copied onto the chunk that carries text held back until
# the end of the stream.
_CHUNK_IDENTITY_FIELDS = ("id", "object", "created", "model", "system_fingerprint")


def _as_index(value: Any, default: int) -> int:
    """An ``index`` field, or *default* when it is missing or not an integer."""
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _append_text(delta: dict, where: tuple, tail: str) -> None:
    """Append *tail* to the text at *where* (a window key without the
    choice index) in *delta*, a dict the caller owns."""
    field = where[0]
    if field == "tool_calls":
        calls = list(delta["tool_calls"]) if isinstance(delta.get("tool_calls"), list) else []
        for pos, call in enumerate(calls):
            if isinstance(call, dict) and _as_index(call.get("index"), pos) == where[1]:
                function = call["function"] if isinstance(call.get("function"), dict) else {}
                arguments = _text(function.get("arguments")) + tail
                calls[pos] = {**call, "function": {**function, "arguments": arguments}}
                break
        else:
            calls.append({"index": where[1], "function": {"arguments": tail}})
        delta["tool_calls"] = calls
    elif field == "function_call":
        function = delta["function_call"] if isinstance(delta.get("function_call"), dict) else {}
        delta["function_call"] = {
            **function,
            "arguments": _text(function.get("arguments")) + tail,
        }
    else:
        delta[field] = _text(delta.get(field)) + tail


class _StreamedText:
    """Redacts the text a model generates in streamed completion chunks.

    Each chunk is cloned with all of its fields, and only generated text is
    replaced: the delta's ``content``, ``reasoning_content``, ``reasoning``
    and ``refusal``, and the ``arguments`` of tool calls and function calls.
    That text goes through one window of a windowed
    :class:`~admina.sdk.streaming.StreamRedactor` per choice and field (per
    tool call for arguments), so an entity split across chunks is redacted
    before any of it is sent. The text a window holds back is released with
    the finish chunk of its choice, or by :meth:`remainder` at the end of
    the stream. Token texts in ``logprobs`` and comment lines are redacted
    one by one. Without a PII redactor the text passes unchanged.
    """

    def __init__(self, pii_redactor: Any = None) -> None:
        self._pii = pii_redactor
        self._windows: dict[tuple, Any] = {}
        self._identity: dict[str, Any] = {}

    def chunk(self, chunk: dict) -> dict:
        """*chunk* with its generated text redacted."""
        self._identity = {k: chunk[k] for k in _CHUNK_IDENTITY_FIELDS if k in chunk}
        choices = chunk.get("choices")
        if not isinstance(choices, list):
            return chunk
        return {**chunk, "choices": [self._choice(pos, c) for pos, c in enumerate(choices)]}

    def comment(self, line: str) -> str:
        """An SSE comment line, redacted."""
        return line if self._pii is None else self._pii.redact(line)["redacted_text"]

    def remainder(self) -> dict | None:
        """A last chunk with the text still held back, or None."""
        choices = []
        for index in sorted({key[0] for key in self._windows}):
            delta = self._release(index, None)
            if delta is not None:
                choices.append({"index": index, "delta": delta, "finish_reason": None})
        return {**self._identity, "choices": choices} if choices else None

    def _feed(self, key: tuple, text: str) -> str:
        window = self._windows.get(key)
        if window is None:
            window = self._windows[key] = self._new_window()
        return "".join(window.feed(text))

    def _new_window(self) -> Any:
        if self._pii is None:
            return _PassthroughRedactor()
        from admina.sdk.streaming import StreamRedactor

        return StreamRedactor(self._pii)

    def _release(self, index: int, delta: Any) -> dict | None:
        """A copy of *delta* with the text held back for choice *index*
        appended, or None when nothing was held back."""
        tails = []
        for key in [k for k in self._windows if k[0] == index]:
            tail, _summary = self._windows.pop(key).finish()
            if tail:
                tails.append((key[1:], tail))
        if not tails:
            return None
        out = dict(delta) if isinstance(delta, dict) else {}
        for where, tail in tails:
            _append_text(out, where, tail)
        return out

    def _choice(self, pos: int, choice: Any) -> Any:
        if not isinstance(choice, dict):
            return choice
        index = _as_index(choice.get("index"), pos)
        out = dict(choice)
        if isinstance(choice.get("delta"), dict):
            out["delta"] = self._delta(index, choice["delta"])
        if choice.get("logprobs") is not None:
            out["logprobs"] = self._logprobs(choice["logprobs"])
        if choice.get("finish_reason") is not None:
            released = self._release(index, out.get("delta"))
            if released is not None:
                out["delta"] = released
        return out

    def _delta(self, index: int, delta: dict) -> dict:
        out = dict(delta)
        for field in _DELTA_TEXT_FIELDS:
            if isinstance(delta.get(field), str):
                out[field] = self._feed((index, field), delta[field])
        if isinstance(delta.get("tool_calls"), list):
            out["tool_calls"] = [
                self._tool_call(index, pos, call) for pos, call in enumerate(delta["tool_calls"])
            ]
        function = delta.get("function_call")
        if isinstance(function, dict) and isinstance(function.get("arguments"), str):
            arguments = self._feed((index, "function_call"), function["arguments"])
            out["function_call"] = {**function, "arguments": arguments}
        return out

    def _tool_call(self, index: int, pos: int, call: Any) -> Any:
        function = call.get("function") if isinstance(call, dict) else None
        if not isinstance(function, dict) or not isinstance(function.get("arguments"), str):
            return call
        key = (index, "tool_calls", _as_index(call.get("index"), pos))
        return {
            **call,
            "function": {**function, "arguments": self._feed(key, function["arguments"])},
        }

    def _logprobs(self, logprobs: Any) -> Any:
        if self._pii is None or not isinstance(logprobs, dict):
            return logprobs
        out = dict(logprobs)
        for key in ("content", "refusal"):
            if isinstance(logprobs.get(key), list):
                out[key] = [self._token(entry) for entry in logprobs[key]]
        return out

    def _token(self, entry: Any) -> Any:
        if not isinstance(entry, dict):
            return entry
        out = dict(entry)
        token = entry.get("token")
        if isinstance(token, str):
            redacted = self._pii.redact(token)["redacted_text"]
            if redacted != token:
                out["token"] = redacted
                if entry.get("bytes") is not None:
                    out["bytes"] = list(redacted.encode("utf-8"))
        if isinstance(entry.get("top_logprobs"), list):
            out["top_logprobs"] = [self._token(alt) for alt in entry["top_logprobs"]]
        return out


async def _governed_sse_stream(
    lines: AsyncIterator[str], pii_redactor: Any = None
) -> AsyncIterator[str]:
    """Re-emit upstream SSE lines as governed SSE, one chunk per chunk.

    Each ``data:`` chunk is parsed, its generated text redacted through
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
                "upstream": upstream,
                "action": action,
                "risk_level": risk_level,
                "governance_latency_ms": round(pre.latency_ms, 2),
                "checks": {k: safe_serialize(v) for k, v in pre.checks.items()},
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
            gateway_http_client, gateway_upstreams, gateway_stream_mode).
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
    async def chat_completions(request: Request):
        state = get_state()
        cfg = get_settings()
        route = _select_upstream(request, state, cfg)
        if route is None:
            return _unknown_upstream()
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
        # Same estimate as /mcp: the length of the scanned text.
        if 0 < cfg.MAX_REQUEST_TOKENS < len(prompt_text):
            return _error_response(
                413,
                _error(
                    "Request content exceeds the token limit.",
                    "invalid_request_error",
                    "request_tokens_exceeded",
                ),
            )
        event_id = uuid.uuid4().hex

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

        await _record_forensic(
            state.forensic_box,
            event_id=event_id,
            agent_id=agent_id,
            session_id=session_id,
            upstream=route.name,
            action=action,
            risk_level=pre.gov_response.risk_level,
            pre=pre,
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
        if isinstance(data.get("choices"), list):
            data["choices"], _ = redact_response_result(data["choices"], state.pii_redactor)
        return JSONResponse(content=data, status_code=resp.status_code)

    return router

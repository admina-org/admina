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

With ``ADMINA_GATEWAY_MODELS_ALLOWLIST`` set, ``GET /v1/models`` lists only
those models and a chat completion for any other model is answered 403
(code ``model_not_allowed``) before it is governed, recorded or forwarded.

A chat completion is forwarded with its body as received and its messages
as governed. ``ADMINA_GATEWAY_FORWARD_FIELDS``, ``ADMINA_GATEWAY_MAX_N`` and
``ADMINA_GATEWAY_MAX_COMPLETION_TOKENS`` (off by default) narrow the other
fields and lower ``n`` and the token limits; a value such a limit refuses is
answered 400 (code ``invalid_value``) before it is governed, recorded or
forwarded (see :mod:`admina.proxy.gateway_body`).

Every chat completion response carries ``X-Admina-Ruleset``, the
:func:`~admina.domains.agent_security.ruleset.ruleset_sha256` of the rules
the gateway scans with (see :mod:`admina.proxy.gateway_scan`), and
``X-Admina-Version``. The firewall scans every string of the request body:
the messages of the roles in ``ADMINA_GATEWAY_SCAN_ROLES``, narrowed by an
accepted ``X-Admina-Scan-Policy`` while ``ADMINA_GATEWAY_SCAN_POLICY_ENABLED``
is on, with tool call ``arguments`` read as JSON, and every other field (tool
definitions, ``response_format``, …). A request with text nested deeper than
the scan depth limit is blocked (see
:mod:`admina.domains.agent_security.scan_policy`).

Once a request has its event id, every response also carries the
governance outcome: ``X-Admina-Event-Id``, ``X-Admina-Action``,
``X-Admina-Risk``, ``X-Admina-Categories`` and ``X-Admina-Record-Hash``
(see :mod:`admina.proxy.gateway_outcome`). A blocked request is answered
as ``ADMINA_GATEWAY_BLOCK_STATUS`` says: with the block message as a
completion (``200``, the default) or with a ``governance_blocked`` error
(``403``).

Each chat completion writes two forensic records: ``gateway_request``
before it is forwarded, with the request id, trace id and recorded headers
of :mod:`admina.proxy.gateway_correlation` and ``request_sha256`` (the
RFC 8785 SHA-256 of the ``messages`` forwarded upstream), and
``gateway_response`` once its response has ended (sent whole, left by the
client, or failed), with the same ``event_id``. With OpenTelemetry on, the
call has a span of its own, a child of the caller's W3C trace context.

The governance pipeline runs in the worker threads of
:mod:`admina.proxy.pipeline_executor`, within the time budget
``ADMINA_GATEWAY_PIPELINE_TIMEOUT``: a request whose decision takes longer,
or whose pipeline raises, is blocked in every governance mode and recorded
with ``checks["pipeline"]``. A guard contract error is handled inside the
pipeline, as ``ADMINA_GUARD_FAIL_MODE`` says.

PII redaction of the completions (see below) runs in the same worker threads
and time budget. A non-streaming completion whose redaction does not finish
(over the budget, or raising) is replaced by the block message; a stream
whose redaction does not finish ends with one ``data: {"error": ...}`` event.

With ``ADMINA_GATEWAY_SCAN_RESPONSE`` the firewall also checks the completion
text (see :mod:`admina.proxy.gateway_response_scan`): a non-streaming
completion before it is returned, blocked when flagged in enforce mode; a
stream after it has ended, recorded only.

Both forward to the upstream route named by the ``X-Admina-Upstream``
request header, or to the default route without it (see
:mod:`admina.proxy.gateway_upstreams`). An unknown route name is answered
with 400 before anything else happens. The upstream receives the route's
own API key, if any, never the caller's credentials; of the caller's
headers, only those listed in ``ADMINA_GATEWAY_FORWARD_HEADERS``.

Upstream responses (stream mode, timeouts and connection pool: see
:mod:`admina.proxy.gateway_transport`):

- An upstream error (non-2xx) reaches the client with its status, body and
  content type, streaming or not.
- Without a response transformation (PII redaction off) a JSON body is
  forwarded unchanged, and so is a stream in ``passthrough`` mode, each SSE
  event as soon as it is complete. Otherwise each SSE chunk is parsed and
  re-serialised (``governed``).
- A timeout before the response starts gets 504, any other transport
  failure 502, with an OpenAI-style error body.
- With ``ADMINA_FORENSIC_FAIL_MODE=closed``, a request whose
  ``gateway_request`` record cannot be written gets 503 (``"code":
  "forensic_unavailable"``) and is not forwarded. A failure during a stream
  ends it with one ``data: {"error": ...}`` event and no ``data: [DONE]``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine, Iterable
from functools import cache, partial
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask
from starlette.types import Receive, Scope, Send

from admina import __version__
from admina.core.trace_context import TraceContext
from admina.core.types import EventType, GovernanceAction
from admina.domains.agent_security.egress import egress_policy_for, resolve_egress_mode
from admina.domains.agent_security.scan_policy import (
    SCAN_POLICY_HEADER,
    SCAN_ROLES,
    ScanScope,
    parse_scan_roles,
    request_texts,
    resolve_scan_scope,
)
from admina.domains.compliance.forensic import ForensicWriteError
from admina.domains.governance import (
    GovernanceResult,
    redact_chat_params,
    run_pipeline,
    safe_serialize,
    unfinished_pipeline_result,
)
from admina.proxy.gateway_body import ForwardedValueError, ForwardSettings
from admina.proxy.gateway_correlation import (
    context_of,
    forward_header_names,
    forwarded_headers,
    record_header_names,
    request_id_header_name,
    request_id_of,
    trace_context_of,
)
from admina.proxy.gateway_outcome import (
    VERSION_HEADER,
    Delivery,
    GatewayCall,
    completion_record,
    firewall_categories,
    messages_sha256,
)
from admina.proxy.gateway_response_scan import (
    completion_texts,
    firewall_decision,
    response_scan_record,
    stream_texts,
)
from admina.proxy.gateway_scan import (
    RULESET_HEADER,
    GatewayScanConfig,
    scan_config_of,
)
from admina.proxy.gateway_transport import DEFAULT_STREAM_MODE, total_deadline
from admina.proxy.gateway_upstreams import UPSTREAM_HEADER, GatewayUpstream, GatewayUpstreams
from admina.proxy.pipeline_executor import PipelineExecutor, PipelineTimeout

logger = logging.getLogger("admina.proxy.gateway")

# Longest X-Admina-Upstream value considered, as for X-Session-Id.
_ROUTE_HEADER_MAX = 128
# Name of the OpenTelemetry span of a chat completion.
_SPAN_NAME = "gateway.chat.completions"


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
    return scan_config_of(state)


def _scan_scope(request: Request, state: Any, cfg: Any, scan: GatewayScanConfig) -> ScanScope:
    """The scan scope of *request*; a scan policy is counted by outcome."""
    scope = resolve_scan_scope(
        request.headers.getlist(SCAN_POLICY_HEADER),
        scan_roles=parse_scan_roles(cfg.ADMINA_GATEWAY_SCAN_ROLES),
        prescan_tags=scan.prescan_tags,
        accepted_rulesets=scan.accepted_rulesets,
        policy_enabled=cfg.ADMINA_GATEWAY_SCAN_POLICY_ENABLED,
    )
    inc_metric = getattr(state, "inc_metric", None)
    if scope.status != "none" and inc_metric is not None:
        inc_metric(f"prescan_{scope.status}")
    return scope


@cache
def _default_executor() -> PipelineExecutor:
    return PipelineExecutor()


def _executor(state: Any) -> PipelineExecutor:
    """The worker threads built at startup, or a default pool."""
    return getattr(state, "pipeline_executor", None) or _default_executor()


async def _govern(
    state: Any,
    cfg: Any,
    pipeline: Callable[[], Coroutine[Any, Any, GovernanceResult]],
    request_id: str,
) -> GovernanceResult:
    """The result of *pipeline*, run in the worker threads (those built at
    startup, or a default pool) within the time budget.

    A pipeline that does not return a result, because it ran over the budget
    or raised, blocks the request in every governance mode: its checks, PII
    redaction included, may not have run. (Guard contract errors do not get
    here: the pipeline handles them itself, as ``ADMINA_GUARD_FAIL_MODE``
    says.)
    """
    budget = cfg.ADMINA_GATEWAY_PIPELINE_TIMEOUT
    started = time.perf_counter()
    try:
        return await _executor(state).run_coroutine(pipeline, timeout=budget)
    except PipelineTimeout:
        logger.warning("Gateway governance exceeded its time budget (%g s): blocked", budget)
        check: dict[str, Any] = {
            "action": "BLOCK",
            "reason": "time_budget_exceeded",
            "budget_ms": round(budget * 1000),
        }
    except Exception as exc:  # noqa: BLE001 — any failure is a governance decision
        logger.error("Gateway governance pipeline failed: %s: blocked", type(exc).__name__)
        logger.debug("Gateway governance pipeline failure", exc_info=True)
        check = {"action": "ERROR", "error": type(exc).__name__}
    return unfinished_pipeline_result(
        check,
        block=True,
        mode="enforce",
        request_id=request_id,
        latency_ms=(time.perf_counter() - started) * 1000,
    )


async def _redacted(state: Any, cfg: Any, job: Callable[[], Any]) -> Any:
    """The result of the redaction *job*, run in the worker threads within
    the time budget; None when it ran over the budget or raised."""
    budget = cfg.ADMINA_GATEWAY_PIPELINE_TIMEOUT
    try:
        return await _executor(state).run(job, timeout=budget)
    except PipelineTimeout:
        logger.warning("Gateway completion redaction exceeded its time budget (%g s)", budget)
    except Exception as exc:  # noqa: BLE001 — the unredacted text is not sent
        logger.error("Gateway completion redaction failed: %s", type(exc).__name__)
        logger.debug("Gateway completion redaction failure", exc_info=True)
    return None


async def _inline(job: Callable[[], Any]) -> Any:
    return job()


def _error(message: str, error_type: str, code: str) -> dict:
    """The ``error`` object of an error body in the OpenAI format."""
    return {"message": message, "type": error_type, "param": None, "code": code}


def _error_response(status: int, error: dict) -> JSONResponse:
    """An error response in the OpenAI format: ``{"error": {...}}``."""
    return JSONResponse(status_code=status, content={"error": error})


def _json_encodable(value: Any) -> bool:
    """True when *value* has a strict JSON encoding in UTF-8, the encoding
    of an upstream request body and of a JSON response: the JSON parser
    also reads ``NaN``, infinities and unpaired surrogates, which have none."""
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        return False
    return True


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


def _models_allowlist(cfg: Any) -> tuple[str, ...]:
    """The model ids of ``ADMINA_GATEWAY_MODELS_ALLOWLIST``; empty = every
    model."""
    return tuple(m.strip() for m in cfg.ADMINA_GATEWAY_MODELS_ALLOWLIST.split(",") if m.strip())


def _model_not_allowed() -> JSONResponse:
    """403 in the OpenAI error format for a model outside the allowlist."""
    error = {
        "message": "The requested model is not available.",
        "type": "invalid_request_error",
        "param": "model",
        "code": "model_not_allowed",
    }
    return _error_response(403, error)


def _invalid_value(exc: ForwardedValueError) -> JSONResponse:
    """400 in the OpenAI error format for a value a forwarding limit refuses."""
    error = {
        "message": str(exc),
        "type": "invalid_request_error",
        "param": exc.field,
        "code": "invalid_value",
    }
    return _error_response(400, error)


def _extract_prompt_text(messages: Any) -> str:
    """Concatenate the text of every chat message for governance scanning.

    Handles both string ``content`` and OpenAI vision-style content parts
    (a list of ``{"type": "text", "text": ...}`` dicts). Non-string,
    non-list content and malformed entries are skipped, and *messages* that
    are not a list have no text.
    """
    if not isinstance(messages, list):
        return ""
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


def _block_response(cfg: Any, model: str, stream: bool, categories: Iterable[str]) -> Response:
    """The response to a blocked chat completion, as
    ``ADMINA_GATEWAY_BLOCK_STATUS`` says: 403 with a ``governance_blocked``
    error (streaming or not), or the block message as a completion."""
    message = cfg.ADMINA_GATEWAY_BLOCK_MESSAGE
    if cfg.ADMINA_GATEWAY_BLOCK_STATUS == 403:
        error = _error(message, "governance_blocked", "governance_blocked")
        return _error_response(403, {**error, "categories": list(categories)})
    if not _json_encodable(model):
        model = "unknown"
    if stream:
        return StreamingResponse(
            _aiter_list(_synthetic_stream(model, message)), media_type="text/event-stream"
        )
    return JSONResponse(content=_synthetic_completion(model, message))


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


# Last event of a stream whose redaction did not finish.
_RESPONSE_NOT_REDACTED = _error(
    "The response could not be redacted.", "server_error", "response_redaction_failed"
)


def _governed_events(text: _StreamedText, line: str) -> list[str]:
    """The SSE events to send for one upstream *line*."""
    if line.startswith(":"):
        return [f"{text.comment(line.rstrip())}\n\n"]
    if line[len("data:") :].strip() == "[DONE]":
        return [*_remainder_events(text), "data: [DONE]\n\n"]
    chunk = _parse_sse_data(line)
    return [] if chunk is None else [_sse_format(text.chunk(chunk))]


def _remainder_events(text: _StreamedText) -> list[str]:
    """A last chunk with the text still held back, if any."""
    last = text.remainder()
    return [] if last is None else [_sse_format(last)]


async def _governed_sse_stream(
    lines: AsyncIterator[str],
    pii_redactor: Any = None,
    redact: Callable[[Callable[[], list[str]]], Awaitable[list[str] | None]] | None = None,
) -> AsyncIterator[str]:
    """Re-emit upstream SSE lines as governed SSE, one chunk per chunk.

    Each ``data:`` chunk is parsed, its text redacted through
    :class:`_StreamedText` (unchanged when *pii_redactor* is None) and
    re-serialised. Comment lines (keep-alives) are forwarded, redacted too;
    data that is not a JSON object is dropped. ``data: [DONE]`` is forwarded when the
    upstream sends it, after a chunk with any text still held back; a
    stream that ends without it gets only that chunk.

    With a redactor, the events of each line are built by *redact* (the
    gateway runs them in its worker threads, see :func:`_redacted`), or in
    place without it. When *redact* returns None the stream ends there, with
    one ``data: {"error": ...}`` event and none of that line's text.
    """
    text = _StreamedText(pii_redactor)
    run = redact if redact is not None and pii_redactor is not None else _inline
    async for line in lines:
        if not line.startswith((":", "data:")):
            continue
        events = await run(partial(_governed_events, text, line))
        if events is None:
            yield _sse_format({"error": _RESPONSE_NOT_REDACTED})
            return
        for event in events:
            yield event
    events = await run(partial(_remainder_events, text))
    if events is None:
        yield _sse_format({"error": _RESPONSE_NOT_REDACTED})
        return
    for event in events:
        yield event


async def _record_forensic(
    forensic_box: Any,
    call: GatewayCall,
    *,
    agent_id: str,
    session_id: str,
    pre: Any,
    prescan: dict,
    trace_id: str | None,
    context: dict[str, str],
    ruleset_sha256: str,
    messages: Any,
) -> str | None:
    """Record the gateway request to the forensic log — the fifth surface
    on the canonical pipeline — and return its ``record_hash`` (None
    without a forensic store). Runs off the event loop like /mcp does, the
    ``request_sha256`` of *messages* (the array forwarded upstream) included.

    *prescan* is the scan scope (:meth:`ScanScope.record`)."""
    if forensic_box is None:
        return None
    event: dict[str, Any] = {
        "event_id": call.event_id,
        "event_type": EventType.GATEWAY_REQUEST,
        "agent_id": agent_id,
        "session_id": session_id,
        "request_id": call.request_id,
        "trace_id": trace_id,
        "context": context,
        "method": "chat.completions",
        "upstream": call.upstream,
        "action": call.action,
        "risk_level": call.risk_level,
        "categories": list(call.categories),
        "governance_latency_ms": round(pre.latency_ms, 2),
        "checks": {k: safe_serialize(v) for k, v in pre.checks.items()},
        "prescan": prescan,
        "ruleset_sha256": ruleset_sha256,
    }
    if call.would_action is not None:
        event["would_action"] = call.would_action

    def write() -> Any:
        event["request_sha256"] = messages_sha256(messages)
        return forensic_box.record(event)

    return _record_hash(await asyncio.get_running_loop().run_in_executor(None, write))


def _record_hash(result: Any) -> str | None:
    """The ``record_hash`` of a forensic store's result, or None."""
    value = result.get("record_hash") if isinstance(result, dict) else None
    return value if isinstance(value, str) else None


async def _record(forensic_box: Any, event: dict) -> None:
    """Append *event* to the forensic log, off the event loop."""
    if forensic_box is None:
        return
    await asyncio.get_running_loop().run_in_executor(None, forensic_box.record, event)


async def _record_completion(forensic_box: Any, event: dict) -> None:
    """Append the completion record *event*, off the event loop. The write
    is handed to a thread before anything is awaited, so it is done even
    when the request is cancelled meanwhile; a failure is logged."""
    if forensic_box is None:
        return
    write = asyncio.get_running_loop().run_in_executor(None, forensic_box.record, event)
    try:
        await write
    except Exception as exc:  # noqa: BLE001 — the response has been sent
        logger.error("Gateway completion record failed: %s", type(exc).__name__)


def _open_trace(
    state: Any, call: GatewayCall, incoming: TraceContext | None
) -> TraceContext | None:
    """Start the span of *call* when OpenTelemetry is on, a child of
    *incoming*; return the call's trace context: the span's, else
    *incoming*."""
    exporter = getattr(state, "otel_exporter", None)
    if exporter is None or not exporter.enabled:
        return incoming
    call.span = exporter.start_span(
        _SPAN_NAME,
        parent=incoming,
        attributes={"admina.event_id": call.event_id, "admina.upstream": call.upstream},
    )
    if call.span is None:
        return incoming
    ids = call.span.get_span_context()
    return TraceContext.of(
        f"{ids.trace_id:032x}",
        f"{ids.span_id:016x}",
        int(ids.trace_flags),
        incoming.tracestate if incoming is not None else None,
    )


def _end_span(span: Any, record: dict) -> None:
    """End *span* with the outcome of its completion *record*."""
    if span is None:
        return
    span.set_attribute("admina.action", record["action"])
    span.set_attribute("http.response.status_code", record["status_code"])
    if record["cancelled"]:
        span.set_attribute("admina.cancelled", True)
    if record["error"] is not None:
        span.set_attribute("error.type", record["error"])
    span.end()


async def _end_call(
    state: Any,
    call: GatewayCall,
    status_code: int,
    delivery: Delivery,
    body: bytes | None,
    sent: bool,
) -> None:
    """End *call*, whose response has *status_code* and, unless streamed,
    *body*: end its span and write its completion record. *sent* is False
    when sending the response raised."""
    if body is not None:
        delivery.body(body)
    if not sent:
        delivery.completed = False
    record = completion_record(call, status_code, delivery)
    _end_span(call.span, record)
    await _record_completion(state.forensic_box, record)


class _Finished(Response):
    """A response sent as it is, then *end* awaited with whether sending it
    returned: once it has been sent whole, left by the client, or failed."""

    def __init__(self, response: Response, end: Callable[[bool], Awaitable[None]]) -> None:
        # The wrapped response renders and sends itself.
        self.response = response
        self.end = end
        self.background = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        sent = False
        try:
            await self.response(scope, receive, send)
            sent = True
        finally:
            await self.end(sent)


def _finish(state: Any, call: GatewayCall, response: Response) -> Response:
    """*response* with the outcome headers of *call*, ending the call once
    it has been sent: the bytes of a stream are counted as they go out."""
    response.headers.update(call.headers())
    delivery = Delivery()
    body = None
    if isinstance(response, StreamingResponse):
        response.body_iterator = delivery.relay(response.body_iterator)
    else:
        body = bytes(response.body)
    return _Finished(
        response, partial(_end_call, state, call, response.status_code, delivery, body)
    )


def _scans_response(cfg: Any) -> bool:
    return bool(cfg.ADMINA_GATEWAY_SCAN_RESPONSE and cfg.INJECTION_FAST_PATH_ENABLED)


async def _scan_response(
    state: Any,
    cfg: Any,
    texts_of: Callable[[], list[str]],
    *,
    request_event_id: str,
    agent_id: str,
    session_id: str,
    upstream: str,
    stream: bool,
) -> GovernanceResult:
    """Scan the completion text given by ``texts_of()`` in the worker
    threads, within the time budget, and record the outcome."""
    event_id = uuid.uuid4().hex
    mode = cfg.GOVERNANCE_MODE

    async def check() -> GovernanceResult:
        return firewall_decision(state.firewall, texts_of(), mode)

    result = await _govern(state, cfg, check, event_id)
    await _record(
        state.forensic_box,
        response_scan_record(
            result,
            event_id=event_id,
            request_event_id=request_event_id,
            agent_id=agent_id,
            session_id=session_id,
            upstream=upstream,
            stream=stream,
        ),
    )
    return result


async def _collected(chunks: AsyncIterator[Any], sent: list[Any]) -> AsyncIterator[Any]:
    """*chunks*, each one also appended to *sent*."""
    async for chunk in chunks:
        sent.append(chunk)
        yield chunk


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


def _failure_response(
    route: GatewayUpstream, exc: Exception, call: GatewayCall | None = None
) -> JSONResponse:
    if call is not None:
        call.failed(exc)
    return _error_response(*_failure(route, exc))


# Error bodies (OpenAI format) for a chat completion that raised in the
# gateway once it had its event id; they never carry the exception text.
_BODY_NOT_ENCODABLE = _error(
    "The request body has a value that JSON cannot encode "
    "(a number that is not finite, or an unpaired surrogate).",
    "invalid_request_error",
    "invalid_request_body",
)
_GATEWAY_FAILED = _error(
    "The gateway could not complete the request.", "server_error", "internal_error"
)
# ADMINA_FORENSIC_FAIL_MODE=closed: the request record was not written.
_FORENSIC_UNAVAILABLE = _error(
    "The forensic record of the request could not be written.",
    "server_error",
    "forensic_unavailable",
)


def _unexpected_failure(call: GatewayCall, exc: Exception, body: dict) -> JSONResponse:
    """The response to *call*, which raised *exc* unexpectedly: 503 when its
    forensic record was not written (closed fail mode; the request was not
    forwarded), 400 when the request *body* has no strict JSON encoding (the
    upstream request cannot be built), else 500. The call records the class
    of *exc*."""
    call.failed(exc)
    if isinstance(exc, ForensicWriteError):
        logger.error("Gateway request not forwarded: its forensic record was not written")
        return _error_response(503, _FORENSIC_UNAVAILABLE)
    if isinstance(exc, (ValueError, TypeError, RecursionError)) and not _json_encodable(body):
        logger.warning("Gateway request body has no JSON encoding: %s", type(exc).__name__)
        return _error_response(400, _BODY_NOT_ENCODABLE)
    logger.error("Gateway chat completion failed: %s", type(exc).__name__)
    logger.debug("Gateway chat completion failure", exc_info=True)
    return _error_response(500, _GATEWAY_FAILED)


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
    on_failure: Callable[[BaseException], None] | None = None,
) -> AsyncIterator[Any]:
    """Send *chunks* on as they come, within the total *deadline*.

    An upstream failure ends the stream with one ``data: {"error": ...}``
    event and no ``data: [DONE]``, and is passed to *on_failure*. The
    upstream response is closed in every case, also when the client goes
    away.
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
                if on_failure is not None:
                    on_failure(exc)
                _status, error = _failure(route, exc)
                yield _sse_format({"error": error})
                return
            yield chunk
    finally:
        await stream_cm.__aexit__(None, None, None)


async def _chat_completion(
    request: Request, state: Any, cfg: Any, scan: GatewayScanConfig
) -> tuple[Response, GatewayCall | None]:
    """Govern one chat completion and relay it upstream.

    Returns the response and, once the request has its event id, its call:
    the route handler adds the ruleset and version headers and, with
    :func:`_finish`, the outcome headers and the end of the call. Once the
    call exists, an exception is answered by :func:`_unexpected_failure`,
    so that response too gets the outcome headers, the completion record
    and the end of the span.
    """
    arrived = time.perf_counter()
    route = _select_upstream(request, state, cfg)
    if route is None:
        return _unknown_upstream(), None
    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError, RecursionError):
        body = None
    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"}), None
    allowed_models = _models_allowlist(cfg)
    if allowed_models and body.get("model") not in allowed_models:
        return _model_not_allowed(), None
    try:
        fields = ForwardSettings.of(cfg).fields(body)
    except ForwardedValueError as exc:
        return _invalid_value(exc), None
    prompt_text = _extract_prompt_text(body.get("messages") or [])
    if 0 < cfg.ADMINA_GATEWAY_MAX_PROMPT_CHARS < len(prompt_text):
        too_long = _error(
            "The message text exceeds the length limit.",
            "invalid_request_error",
            "prompt_too_long",
        )
        return _error_response(413, too_long), None
    call = GatewayCall(
        event_id=uuid.uuid4().hex,
        upstream=route.name,
        stream=bool(body.get("stream", False)),
        arrived=arrived,
        request_id=request_id_of(
            request.headers, request_id_header_name(cfg.ADMINA_GATEWAY_REQUEST_ID_HEADER)
        ),
    )
    try:
        response = await _governed_call(
            request, state, cfg, scan, route, call, body, fields, prompt_text
        )
    except Exception as exc:  # noqa: BLE001 — the call still ends with its outcome
        response = _unexpected_failure(call, exc, body)
    return response, call


def _forwarded_messages(pre: GovernanceResult, messages: list) -> list:
    """The messages to forward: those of the PII redaction when it masked
    something, else *messages* as received. A redacted body without a list
    of messages is logged as an error and *messages* are forwarded."""
    if not pre.checks.get("pii_redaction", {}).get("count", 0):
        return messages
    params = (pre.redacted_body or {}).get("params")
    redacted = params.get("messages") if isinstance(params, dict) else None
    if not isinstance(redacted, list):
        logger.error(
            "Gateway PII redaction returned no list of messages: forwarding them as received"
        )
        return messages
    return redacted


async def _governed_call(
    request: Request,
    state: Any,
    cfg: Any,
    scan: GatewayScanConfig,
    route: GatewayUpstream,
    call: GatewayCall,
    body: dict,
    fields: dict,
    prompt_text: str,
) -> Response:
    """The response to *call*, whose request has JSON *body* and message
    text *prompt_text*: governed, recorded and, unless blocked, relayed to
    *route* with the top-level *fields* (see
    :mod:`admina.proxy.gateway_body`) and the governed messages."""
    event_id = call.event_id
    messages = body.get("messages") or []
    model = body.get("model", "unknown")
    stream = call.stream
    session_id = re.sub(r"[\r\n]", "", request.headers.get("X-Session-Id", "default"))[:128]
    agent_id = re.sub(r"[\r\n]", "", request.headers.get("X-Agent-Id", "gateway"))[:128]
    scope = _scan_scope(request, state, cfg, scan)
    trace = _open_trace(state, call, trace_context_of(request.headers))

    def pipeline() -> Coroutine[Any, Any, GovernanceResult]:
        # Called in a worker thread: selecting the texts to scan runs there too.
        scanned = request_texts(body, scope)
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
            egress_policy=egress_policy_for(state.egress_policy, "gateway"),
            egress_mode=resolve_egress_mode(cfg.GOVERNANCE_MODE),
            scan_texts=scanned.texts,
            scan_truncated=scanned.truncated,
            redact_params=redact_chat_params,
        )

    pre = await _govern(state, cfg, pipeline, event_id)
    call.action = pre.gov_response.action  # uppercase: ALLOW/BLOCK/CIRCUIT_BREAK
    call.risk_level = pre.gov_response.risk_level
    call.categories = firewall_categories(pre.checks.get("firewall"))
    if pre.would_action is not None:
        call.would_action = str(safe_serialize(pre.would_action)).upper()

    fwd_messages = _forwarded_messages(pre, messages)
    call.record_hash = await _record_forensic(
        state.forensic_box,
        call,
        agent_id=agent_id,
        session_id=session_id,
        pre=pre,
        prescan=scope.record(),
        trace_id=trace.trace_id if trace is not None else None,
        context=context_of(request.headers, record_header_names(cfg.ADMINA_GATEWAY_RECORD_HEADERS)),
        ruleset_sha256=scan.ruleset_sha256,
        messages=fwd_messages,
    )

    if call.action in ("BLOCK", "CIRCUIT_BREAK"):
        return _block_response(cfg, model, stream, call.categories)

    url = f"{route.url}/chat/completions"
    forwarded = forward_header_names(cfg.ADMINA_GATEWAY_FORWARD_HEADERS)
    headers = {
        **forwarded_headers(request.headers, forwarded, trace),
        "X-Admina-Event-Id": event_id,
        **route.auth_headers(),
    }
    forward_body = {**fields, "messages": fwd_messages}
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
            return _failure_response(route, exc, call)
        call.upstream_status = upstream.status_code

        if not _is_success(upstream.status_code):
            try:
                async with asyncio.timeout_at(deadline):
                    content = await upstream.aread()
            except (TimeoutError, httpx.RequestError) as exc:
                return _failure_response(route, exc, call)
            finally:
                await stream_cm.__aexit__(None, None, None)
            return _as_received(upstream.status_code, upstream.headers, content)

        try:
            passthrough = getattr(
                state, "gateway_stream_mode", DEFAULT_STREAM_MODE
            ) == "passthrough" and not _transforms_response(cfg)
            if passthrough:
                chunks: AsyncIterator[Any] = _sse_events(upstream.aiter_bytes())
                content_type = upstream.headers.get("content-type") or "text/event-stream"
            else:
                pii = state.pii_redactor if cfg.PII_REDACTION_ENABLED else None
                chunks = _governed_sse_stream(
                    upstream.aiter_lines(), pii, partial(_redacted, state, cfg)
                )
                content_type = "text/event-stream"
            scan = None
            if _scans_response(cfg):
                # The text sent is scanned once the response is complete.
                sent: list[Any] = []
                chunks = _collected(chunks, sent)
                scan = BackgroundTask(
                    _scan_response,
                    state,
                    cfg,
                    lambda: stream_texts(sent),
                    request_event_id=event_id,
                    agent_id=agent_id,
                    session_id=session_id,
                    upstream=route.name,
                    stream=True,
                )
            return StreamingResponse(
                _relay(chunks, stream_cm, deadline, route, call.failed),
                status_code=upstream.status_code,
                headers={"content-type": content_type},
                background=scan,
            )
        except BaseException:
            # No relay owns the upstream response: it is closed here.
            await stream_cm.__aexit__(None, None, None)
            raise

    try:
        async with asyncio.timeout_at(deadline):
            resp = await client.post(url, json=forward_body, headers=headers)
    except (TimeoutError, httpx.RequestError) as exc:
        return _failure_response(route, exc, call)
    call.upstream_status = resp.status_code
    if _scans_response(cfg) and _is_success(resp.status_code):
        completion = _json_object(resp.content)
        if completion is not None:
            checked = await _scan_response(
                state,
                cfg,
                lambda: completion_texts(completion),
                request_event_id=event_id,
                agent_id=agent_id,
                session_id=session_id,
                upstream=route.name,
                stream=False,
            )
            if checked.action == GovernanceAction.BLOCK:
                call.action = "BLOCK"
                call.risk_level = str(safe_serialize(checked.risk_level)).upper()
                call.categories = firewall_categories(checked.checks.get("response_firewall"))
                return _block_response(cfg, model, False, call.categories)
    if not (_transforms_response(cfg) and _is_success(resp.status_code)):
        return _as_received(resp.status_code, resp.headers, resp.content)
    data = _json_object(resp.content)
    if data is None:
        return _error_response(502, _UPSTREAM_INVALID)
    redacted = await _redacted(state, cfg, partial(_redacted_completion, data, state.pii_redactor))
    if redacted is None:
        # The completion could not be redacted: the block message instead.
        call.action = "BLOCK"
        return _block_response(cfg, model, False, call.categories)
    return JSONResponse(content=redacted, status_code=resp.status_code)


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
        allow = _models_allowlist(cfg)
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
        response, call = await _chat_completion(request, state, get_settings(), scan)
        response.headers[RULESET_HEADER] = scan.ruleset_sha256
        response.headers[VERSION_HEADER] = __version__
        return response if call is None else _finish(state, call, response)

    @router.get("/admina/ruleset", summary="Active firewall ruleset")
    async def active_ruleset() -> dict[str, Any]:
        scan = _scan_config(get_state())
        cfg = get_settings()
        roles = parse_scan_roles(cfg.ADMINA_GATEWAY_SCAN_ROLES)
        return {
            "ruleset_sha256": scan.ruleset_sha256,
            "engine": scan.engine,
            "admina_core_version": scan.admina_core_version,
            "admina_version": __version__,
            "accepted_prescan_rulesets": list(scan.accepted_rulesets),
            "prescan_tags": sorted(scan.prescan_tags),
            "scan_roles": [role for role in SCAN_ROLES if role in roles],
            "scan_policy_enabled": cfg.ADMINA_GATEWAY_SCAN_POLICY_ENABLED,
        }

    return router

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

"""Admina — MCP transport adapter.

Converts JSON-RPC 2.0 (MCP wire format) to/from the protocol-agnostic
:class:`GovernanceRequest` / :class:`GovernanceResponse` dataclasses.

The governance engine never sees JSON-RPC — this adapter is the only
place that knows about MCP framing.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from admina.core.types import GovernanceRequest, GovernanceResponse

logger = logging.getLogger("admina.transport.mcp")


def parse_request(
    body: dict[str, Any],
    *,
    session_id: str | None = None,
    agent_id: str | None = None,
) -> GovernanceRequest:
    """Convert a JSON-RPC 2.0 MCP request dict into a GovernanceRequest.

    Args:
        body: The parsed JSON body of an incoming ``POST /mcp`` call.
        session_id: Optional session identifier (from ``X-Session-Id`` header).
        agent_id: Optional agent identifier (from ``X-Agent-Id`` header).

    Returns:
        A populated :class:`GovernanceRequest`.
    """
    method = body.get("method", "unknown")
    params = body.get("params", {})
    content_str = json.dumps(body, default=str)

    return GovernanceRequest(
        content=content_str,
        method=method,
        direction="inbound",
        session_id=session_id,
        agent_id=agent_id,
        protocol="mcp",
        metadata={
            "jsonrpc_id": body.get("id"),
            "params": params,
        },
        raw=body,
    )


def format_block_response(
    gov_response: GovernanceResponse,
    original_body: dict[str, Any],
) -> dict[str, Any]:
    """Format a BLOCK governance response as a JSON-RPC 2.0 error.

    Args:
        gov_response: The governance engine's decision.
        original_body: The original JSON-RPC request (for the ``id`` field).

    Returns:
        A JSON-RPC 2.0 error response dict.
    """
    return {
        "jsonrpc": "2.0",
        "id": original_body.get("id"),
        "error": {
            "code": -32600,
            "message": "Request blocked by Admina governance",
            "data": {
                "event_id": gov_response.request_id,
                "reason": "injection_detected",
                "risk_level": gov_response.risk_level,
                "governance_latency_us": round(gov_response.latency_us, 2),
            },
        },
    }


def format_circuit_break_response(
    gov_response: GovernanceResponse,
    original_body: dict[str, Any],
) -> dict[str, Any]:
    """Format a CIRCUIT_BREAK governance response as a JSON-RPC 2.0 error.

    Args:
        gov_response: The governance engine's decision.
        original_body: The original JSON-RPC request (for the ``id`` field).

    Returns:
        A JSON-RPC 2.0 error response dict.
    """
    return {
        "jsonrpc": "2.0",
        "id": original_body.get("id"),
        "error": {
            "code": -32000,
            "message": "Circuit breaker activated: reasoning loop detected",
            "data": {
                "event_id": gov_response.request_id,
                "reason": "reasoning_loop",
                "similarity": gov_response.metadata.get("similarity"),
                "governance_latency_us": round(gov_response.latency_us, 2),
            },
        },
    }


def format_allow_headers(
    gov_response: GovernanceResponse,
    *,
    forensic_hash: str | None = None,
) -> dict[str, str]:
    """Build the extra HTTP headers added to a successful proxy response.

    Args:
        gov_response: The governance engine's ALLOW decision.
        forensic_hash: Optional truncated forensic record hash.

    Returns:
        A dict of HTTP header name → value.
    """
    headers: dict[str, str] = {
        "X-Admina-Event-Id": gov_response.request_id,
        "X-Admina-Governance-Action": gov_response.action,
        "X-Admina-Latency-Us": str(round(gov_response.latency_us, 2)),
    }
    if forensic_hash:
        headers["X-Admina-Forensic-Hash"] = forensic_hash
    return headers


def extract_text_fields(obj: Any, depth: int = 0) -> list[str]:
    """Recursively extract all string values from a dict/list.

    Args:
        obj: A parsed JSON value (dict, list, or scalar).
        depth: Current recursion depth (capped at 5).

    Returns:
        A flat list of string values found.
    """
    if depth > 5:
        return []
    texts: list[str] = []
    if isinstance(obj, str):
        texts.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            texts.extend(extract_text_fields(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            texts.extend(extract_text_fields(item, depth + 1))
    return texts

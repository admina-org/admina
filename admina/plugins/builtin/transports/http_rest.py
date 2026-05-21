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

"""Admina — HTTP REST transport adapter.

Provides a plain ``POST /api/govern`` endpoint for non-MCP callers
(OpenClaw REST, n8n webhooks, direct API consumers).
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from admina.core.types import GovernanceRequest, GovernanceResponse
from admina.plugins.base import BaseTransportAdapter

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger("admina.plugins.transports.http_rest")


class HTTPRESTTransportAdapter(BaseTransportAdapter):
    """Transport adapter for plain HTTP REST requests.

    Exposes ``POST /api/govern`` accepting a JSON body with ``content``,
    optional ``method``, ``session_id``, ``user_id``, and ``metadata``.
    """

    async def parse_request(self, raw_request: Any) -> GovernanceRequest:
        """Convert a REST JSON body into a GovernanceRequest.

        Expected body::

            {
                "content": "text to govern",
                "method": "optional.method",
                "session_id": "optional",
                "user_id": "optional",
                "metadata": {}
            }
        """
        if isinstance(raw_request, dict):
            body = raw_request
        else:
            body = json.loads(raw_request) if isinstance(raw_request, (str, bytes)) else {}

        return GovernanceRequest(
            content=body.get("content", ""),
            method=body.get("method", "rest.call"),
            direction="inbound",
            session_id=body.get("session_id"),
            user_id=body.get("user_id"),
            protocol="http_rest",
            metadata=body.get("metadata", {}),
            raw=body,
        )

    async def format_response(
        self,
        gov_response: GovernanceResponse,
        original: Any,
    ) -> Any:
        """Convert a GovernanceResponse into a REST JSON dict."""
        return {
            "request_id": gov_response.request_id,
            "action": gov_response.action,
            "risk_level": gov_response.risk_level,
            "content": gov_response.content,
            "domain": gov_response.domain,
            "latency_us": round(gov_response.latency_us, 2),
            "metadata": gov_response.metadata,
        }

    def register_routes(self, app: FastAPI) -> None:
        """Register ``POST /api/govern`` on the FastAPI app."""
        # Route registration is deferred to the proxy bootstrap;
        # this method is a no-op when called during plugin discovery.
        pass

    @property
    def protocol_name(self) -> str:
        """Protocol identifier."""
        return "http_rest"

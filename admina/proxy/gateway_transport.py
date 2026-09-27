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

"""Transport of the OpenAI-compatible gateway: stream mode, timeouts, pool.

The gateway talks to its upstream routes through an HTTP client of its own,
built at startup by :func:`build_gateway_http_client`:

- ``ADMINA_GATEWAY_TIMEOUT_CONNECT`` bounds opening a connection and
  waiting for a free one in the pool; ``ADMINA_GATEWAY_TIMEOUT_READ``
  bounds each wait for upstream bytes and each write of the request. 0
  means no limit. ``ADMINA_GATEWAY_TIMEOUT_TOTAL`` (the whole exchange) is
  enforced by the gateway itself, see :func:`total_deadline`.
- ``ADMINA_GATEWAY_MAX_CONNECTIONS`` and
  ``ADMINA_GATEWAY_MAX_KEEPALIVE_CONNECTIONS`` size its connection pool.

The stream mode (``passthrough`` or ``governed``) is
``ADMINA_GATEWAY_STREAM_MODE`` when set, else ``gateway.stream_mode`` of
``admina.yaml``, else ``passthrough``: see :func:`resolve_stream_mode`.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from admina.core.config import GATEWAY_STREAM_MODES, GatewayConfig

__all__ = [
    "DEFAULT_STREAM_MODE",
    "build_gateway_http_client",
    "gateway_limits",
    "gateway_timeout",
    "resolve_stream_mode",
    "total_deadline",
]

DEFAULT_STREAM_MODE = GATEWAY_STREAM_MODES[0]


def resolve_stream_mode(settings: Any, gateway: GatewayConfig | None = None) -> str:
    """The stream mode: the environment, then ``admina.yaml``, then the default."""
    return (
        settings.ADMINA_GATEWAY_STREAM_MODE
        or (gateway.stream_mode if gateway is not None else "")
        or DEFAULT_STREAM_MODE
    )


def _seconds(value: float) -> float | None:
    """A timeout setting in seconds; 0 means no limit (None for httpx)."""
    return float(value) if value > 0 else None


def gateway_timeout(settings: Any) -> httpx.Timeout:
    """Per-operation timeouts of the gateway's upstream client."""
    connect = _seconds(settings.ADMINA_GATEWAY_TIMEOUT_CONNECT)
    read = _seconds(settings.ADMINA_GATEWAY_TIMEOUT_READ)
    return httpx.Timeout(connect=connect, read=read, write=read, pool=connect)


def gateway_limits(settings: Any) -> httpx.Limits:
    """Connection pool limits of the gateway's upstream client."""
    return httpx.Limits(
        max_connections=settings.ADMINA_GATEWAY_MAX_CONNECTIONS,
        max_keepalive_connections=settings.ADMINA_GATEWAY_MAX_KEEPALIVE_CONNECTIONS,
    )


def build_gateway_http_client(settings: Any) -> httpx.AsyncClient:
    """The gateway's upstream client, with the configured timeouts and pool."""
    return httpx.AsyncClient(timeout=gateway_timeout(settings), limits=gateway_limits(settings))


def total_deadline(settings: Any) -> float | None:
    """Event-loop time by which the upstream exchange must be over, or None."""
    total = _seconds(settings.ADMINA_GATEWAY_TIMEOUT_TOTAL)
    return None if total is None else asyncio.get_running_loop().time() + total

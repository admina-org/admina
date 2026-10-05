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

"""Firewall ruleset and prescan settings of the OpenAI-compatible gateway.

Resolved once at startup (:func:`build_gateway_scan_config`) from the
firewall engine in use and ``admina.yaml``: the active ruleset
(:func:`~admina.domains.agent_security.ruleset.ruleset_sha256`), the other
rulesets a request may declare in ``X-Admina-Scan-Policy``
(``gateway.prescan_rulesets``) and the tags whose blocks it may declare as
already scanned (``gateway.prescan_tags``).

:class:`RulesetHeaderMiddleware` puts the active ruleset on every response
of ``/v1/chat/completions``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from admina.core.config import AdminaConfig
from admina.domains.agent_security.ruleset import ruleset_document, ruleset_object

__all__ = [
    "CHAT_COMPLETIONS_PATH",
    "RULESET_HEADER",
    "GatewayScanConfig",
    "RulesetHeaderMiddleware",
    "build_gateway_scan_config",
    "default_gateway_scan_config",
    "scan_config_of",
]

#: Response header carrying the active ruleset.
RULESET_HEADER = "X-Admina-Ruleset"
#: The gateway route whose responses carry :data:`RULESET_HEADER`.
CHAT_COMPLETIONS_PATH = "/v1/chat/completions"


@dataclass(frozen=True)
class GatewayScanConfig:
    """The gateway's firewall ruleset and prescan settings."""

    #: ruleset_sha256() of the configuration, for the engine in use.
    ruleset_sha256: str
    #: "python" or "rust".
    engine: str
    #: Version of admina-core behind the rust engine, else None.
    admina_core_version: str | None
    #: gateway.prescan_rulesets, lowercase.
    prescan_rulesets: tuple[str, ...] = ()
    #: gateway.prescan_tags.
    prescan_tags: frozenset[str] = frozenset()
    #: ruleset_document() whose SHA-256 is ruleset_sha256.
    ruleset_document: str = ""

    @property
    def accepted_rulesets(self) -> tuple[str, ...]:
        """Rulesets accepted in ``X-Admina-Scan-Policy``: the active one
        first, then ``gateway.prescan_rulesets``, without duplicates."""
        return tuple(dict.fromkeys((self.ruleset_sha256, *self.prescan_rulesets)))


def build_gateway_scan_config(firewall: Any, config: AdminaConfig | None) -> GatewayScanConfig:
    """The scan settings for *firewall* (its ``engine``, ``"python"`` when
    it names none) and *config* (``None`` = the defaults)."""
    config = config or AdminaConfig()
    engine = getattr(firewall, "engine", "python")
    builtin = ruleset_object(config, engine=engine)["builtin"]
    core_version = builtin["admina_core_version"] if engine == "rust" else None
    document = ruleset_document(config, engine=engine, admina_core_version=core_version)
    return GatewayScanConfig(
        ruleset_sha256=hashlib.sha256(document.encode("utf-8")).hexdigest(),
        ruleset_document=document,
        engine=engine,
        admina_core_version=core_version,
        prescan_rulesets=tuple(config.gateway.prescan_rulesets),
        prescan_tags=frozenset(config.gateway.prescan_tags),
    )


@cache
def default_gateway_scan_config() -> GatewayScanConfig:
    """Scan settings of a gateway router used without the proxy startup:
    the default configuration on the Python engine."""
    return build_gateway_scan_config(None, None)


def scan_config_of(state: Any) -> GatewayScanConfig:
    """The scan settings resolved at startup into *state*, or the defaults
    when there are none."""
    return getattr(state, "gateway_scan", None) or default_gateway_scan_config()


def _internal_error() -> JSONResponse:
    """500 in the OpenAI error format, without the exception's text."""
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "message": "The gateway could not complete the request.",
                "type": "server_error",
                "param": None,
                "code": "internal_error",
            }
        },
    )


class RulesetHeaderMiddleware:
    """Put :data:`RULESET_HEADER` on every response of
    :data:`CHAT_COMPLETIONS_PATH`, including those that other middleware
    produce (401 from authentication, 413 from the body size limit).

    An exception that reaches this middleware before a response has started
    gets a 500 in the OpenAI error format, with the header; the exception is
    then raised again, so the server still logs it. Added as the outermost
    middleware.

    Args:
        app: The ASGI application.
        get_ruleset: Returns the active ruleset; read on every request.
    """

    def __init__(self, app: ASGIApp, get_ruleset: Callable[[], str]) -> None:
        self.app = app
        self._get_ruleset = get_ruleset

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or path.rstrip("/") != CHAT_COMPLETIONS_PATH:
            await self.app(scope, receive, send)
            return
        ruleset = self._get_ruleset()
        started = False

        async def send_with_ruleset(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                MutableHeaders(scope=message).setdefault(RULESET_HEADER, ruleset)
            await send(message)

        try:
            await self.app(scope, receive, send_with_ruleset)
        except Exception:
            if not started:
                await _internal_error()(scope, receive, send_with_ruleset)
            raise

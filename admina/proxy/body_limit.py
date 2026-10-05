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

"""Request body size limit for every HTTP route.

:class:`BodyLimitMiddleware` is a plain ASGI middleware. A request whose
``Content-Length`` is over the limit gets 413 before the application runs.
A body sent without a length (chunked) is counted as the application reads
it: the read that goes over the limit raises :class:`RequestBodyTooLarge`
into the application and the request gets 413, in place of any response
the application then tries to send. Either way no parser sees the body.

The 413 body is in the OpenAI error format on the gateway (``/v1``) and
``{"detail": ...}`` elsewhere, like the other errors of each surface.
"""

from __future__ import annotations

from collections.abc import Callable

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = ["BodyLimitMiddleware", "RequestBodyTooLarge"]

_GATEWAY_PREFIX = "/v1"


class RequestBodyTooLarge(Exception):
    """The request body read so far is over the limit."""


def _declared_length(scope: Scope) -> int | None:
    """The request's ``Content-Length``, or None when absent or not a number."""
    for name, value in scope.get("headers", ()):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


def _too_large(scope: Scope) -> JSONResponse:
    path = scope.get("path", "")
    if path == _GATEWAY_PREFIX or path.startswith(_GATEWAY_PREFIX + "/"):
        content: dict = {
            "error": {
                "message": "Request body exceeds the size limit.",
                "type": "invalid_request_error",
                "param": None,
                "code": "request_too_large",
            }
        }
    else:
        content = {"detail": "Request body too large"}
    return JSONResponse(status_code=413, content=content)


class BodyLimitMiddleware:
    """Answer 413 to any HTTP request whose body is over the limit.

    Args:
        app: The ASGI application.
        get_limit: Returns the limit in bytes; read on every request, and
            0 or less means no limit.
    """

    def __init__(self, app: ASGIApp, get_limit: Callable[[], int]) -> None:
        self.app = app
        self._get_limit = get_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        limit = self._get_limit() if scope["type"] == "http" else 0
        if limit <= 0:
            await self.app(scope, receive, send)
            return
        declared = _declared_length(scope)
        if declared is not None and declared > limit:
            await _too_large(scope)(scope, receive, send)
            return

        received = 0
        exceeded = False
        app_started = False
        answered = False

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    raise RequestBodyTooLarge
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal app_started, answered
            if exceeded and not app_started:
                # The application answers a body it could not read (a
                # framework may turn the read error into its own 400): the
                # client gets the 413 instead.
                if not answered:
                    answered = True
                    await _too_large(scope)(scope, receive, send)
                return
            if message["type"] == "http.response.start":
                app_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            # After a refused read, whatever the application raises comes
            # from that read, possibly wrapped (an exception group from a
            # task group on the way, a framework's own error type).
            if not exceeded or app_started:
                raise
            if not answered:
                await _too_large(scope)(scope, receive, send)

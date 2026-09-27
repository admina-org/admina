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

"""Admina — dashboard browser sessions.

The bundled dashboard is a browser application: it cannot hold the API key
in a header without exposing it to page scripts. Instead, the browser
presents the key once to ``POST /api/dashboard/session`` and receives a
short-lived session cookie. This module holds the two rules that make that
safe:

* **What a session token is.** A signed, expiring token bound to the current
  ``ADMINA_API_KEY``. The signature uses a key derived from the API key with a
  fixed purpose label, so a token cannot be confused with any other HMAC
  computed from the same secret, and rotating the API key invalidates every
  outstanding session. The API key itself never leaves the server.

* **Where a session is accepted.** Only on read-only requests to the
  dashboard API (``/api/dashboard/*`` and ``/api/stats``), plus reading and
  ending the session itself. The MCP proxy, the OpenAI-compatible gateway and
  the integration and compliance APIs always require the API key.

The ``Secure`` flag of the cookie follows ``DASHBOARD_COOKIE_SECURE``
(:func:`cookie_secure`): always over HTTPS; over plain HTTP ``true`` sets it,
``auto`` sets it unless the host is a loopback name or address, ``false``
(the default) does not.

Token format (base64url, unpadded)::

    v2.<expiry-unix-seconds>.<nonce-hex>.<hmac-sha256-hex>

where the HMAC covers ``v2.<expiry>.<nonce>``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import secrets
import time

COOKIE_NAME = "admina_dashboard_session"
#: Cookie name used by releases up to 0.12.0. Never accepted; only cleared.
LEGACY_COOKIE_NAME = "admina_session"
#: Browsers send the cookie only to the API, never to ``/mcp`` or ``/v1``.
COOKIE_PATH = "/api/"
SESSION_PATH = "/api/dashboard/session"

DEFAULT_TTL_SECONDS = 3600
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 12 * 3600

_VERSION = "v2"
_PURPOSE = b"admina/dashboard-session/v2"
_MAX_TOKEN_LEN = 256

_READ_METHODS = frozenset({"GET", "HEAD"})
_SESSION_METHODS = frozenset({"GET", "HEAD", "DELETE"})
_SCOPE_PREFIX = "/api/dashboard/"
_SCOPE_PATHS = frozenset({"/api/stats"})


def _signing_key(api_key: str) -> bytes:
    return hmac.new(api_key.encode("utf-8"), _PURPOSE, hashlib.sha256).digest()


def _sign(api_key: str, payload: str) -> str:
    return hmac.new(_signing_key(api_key), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_token(api_key: str, *, ttl: int, now: int | None = None) -> str:
    """Mint a session token valid for *ttl* seconds.

    Raises:
        ValueError: if no API key is configured or *ttl* is out of range.
    """
    if not api_key:
        raise ValueError("a dashboard session requires ADMINA_API_KEY")
    if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
        raise ValueError(
            f"session ttl must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS} seconds"
        )
    exp = (now if now is not None else int(time.time())) + ttl
    payload = f"{_VERSION}.{exp}.{secrets.token_hex(16)}"
    raw = f"{payload}.{_sign(api_key, payload)}".encode("ascii")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def token_expiry(api_key: str, token: str, *, now: int | None = None) -> int | None:
    """Return the expiry of a valid, unexpired token, else ``None``."""
    if not api_key or not token or len(token) > _MAX_TOKEN_LEN:
        return None
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("ascii")
    except (ValueError, UnicodeError, binascii.Error):
        return None
    parts = raw.split(".")
    if len(parts) != 4 or parts[0] != _VERSION:
        return None
    payload, sig = ".".join(parts[:3]), parts[3]
    if not secrets.compare_digest(sig, _sign(api_key, payload)):
        return None
    try:
        exp = int(parts[1])
    except ValueError:
        return None
    if (now if now is not None else int(time.time())) >= exp:
        return None
    return exp


def verify_token(api_key: str, token: str, *, now: int | None = None) -> bool:
    """True if *token* is a valid, unexpired session for *api_key*."""
    return token_expiry(api_key, token, now=now) is not None


def session_allowed(method: str, path: str) -> bool:
    """True if a dashboard session may authenticate *method* on *path*."""
    method = method.upper()
    if path == SESSION_PATH:
        return method in _SESSION_METHODS
    if method not in _READ_METHODS:
        return False
    return path.startswith(_SCOPE_PREFIX) or path in _SCOPE_PATHS


# ── Secure flag of the session cookie (DASHBOARD_COOKIE_SECURE) ──

#: DASHBOARD_COOKIE_SECURE value that decides the flag from the request host.
COOKIE_SECURE_AUTO = "auto"

_TRUE = frozenset({"1", "true", "t", "yes", "y", "on"})
_FALSE = frozenset({"", "0", "false", "f", "no", "n", "off"})


def parse_cookie_secure(value: object) -> bool | str:
    """``DASHBOARD_COOKIE_SECURE`` as ``True``, ``False`` or ``"auto"``.

    Booleans and the usual boolean spellings are accepted, in any case; an
    empty value is ``False``. Any other value raises ``ValueError``.
    """
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text == COOKIE_SECURE_AUTO:
        return COOKIE_SECURE_AUTO
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ValueError("DASHBOARD_COOKIE_SECURE must be true, false or auto")


def is_loopback_host(host: str | None) -> bool:
    """True for ``localhost``, a ``*.localhost`` name or a loopback address
    (``127.0.0.0/8``, ``::1``, an IPv4-mapped loopback address)."""
    if not host:
        return False
    name = host.strip().lower().rstrip(".")
    if name.startswith("[") and name.endswith("]"):
        name = name[1:-1]
    if name == "localhost" or name.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped.is_loopback
    return address.is_loopback


def cookie_secure(mode: bool | str, *, scheme: str, host: str | None) -> bool:
    """Whether the session cookie is marked ``Secure``.

    Always over HTTPS. Over plain HTTP: ``True`` → always; ``"auto"`` → unless
    *host* (the host the browser addressed) is a loopback name or address;
    ``False`` → never.
    """
    if scheme == "https" or mode is True:
        return True
    if mode == COOKIE_SECURE_AUTO:
        return not is_loopback_host(host)
    return False

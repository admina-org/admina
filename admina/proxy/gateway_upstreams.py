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

"""Upstream routes of the OpenAI-compatible gateway.

A route is a name, the base URL of an OpenAI-compatible API and an
optional API key, sent to that upstream as ``Authorization: Bearer <key>``.
A request picks a route with the ``X-Admina-Upstream`` header; without it
the gateway uses the default route. Routes and keys are resolved once, at
startup, by :func:`build_gateway_upstreams`:

- **Routes.** ``ADMINA_GATEWAY_UPSTREAMS`` (``name=url[,name=url…]``) when
  set, replacing ``gateway.upstreams`` of ``admina.yaml`` (URLs and key
  files); otherwise ``gateway.upstreams``; otherwise one route named
  ``default`` to ``ADMINA_GATEWAY_UPSTREAM``. Route names are 1 to 64
  lowercase letters, digits or underscores.
- **Default route.** ``gateway.default_upstream`` when set (it must name a
  route), otherwise the first route.
- **Key of a route.** ``ADMINA_GATEWAY_UPSTREAM_<NAME>_API_KEY[_FILE]``
  (``NAME`` = route name in upper case; read from the process environment
  and the ``.env`` file, like the settings), then
  ``api_key_file`` of the route in ``admina.yaml``, then the default key
  ``ADMINA_GATEWAY_UPSTREAM_API_KEY[_FILE]``; none of them = no
  ``Authorization`` header. Key files follow :mod:`admina.core.secretfile`.

Keys are held as :class:`pydantic.SecretStr`, so representations of the
routes mask them, and error messages never contain a key or a URL.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from pydantic import SecretStr

from admina.core.config import GatewayConfig
from admina.core.secretfile import SecretFileError, read_secret_file, resolve_secret

__all__ = [
    "SINGLE_ROUTE_NAME",
    "UPSTREAM_HEADER",
    "GatewayUpstream",
    "GatewayUpstreamError",
    "GatewayUpstreams",
    "build_gateway_upstreams",
    "settings_environment",
]

UPSTREAM_HEADER = "X-Admina-Upstream"
# Name of the only route when no named routes are configured.
SINGLE_ROUTE_NAME = "default"

_DEFAULT_KEY_SETTING = "ADMINA_GATEWAY_UPSTREAM_API_KEY"
_ROUTES_SETTING = "ADMINA_GATEWAY_UPSTREAMS"
_ROUTE_NAME = re.compile(r"[a-z0-9_]{1,64}")
# A key goes into an HTTP header: visible ASCII only, no spaces or controls.
_KEY_CHARS = re.compile(r"[\x21-\x7e]+")


class GatewayUpstreamError(ValueError):
    """Invalid gateway upstream configuration; the proxy does not start.

    Messages name settings, routes and file paths, never a key or a URL.
    """


@dataclass(frozen=True)
class GatewayUpstream:
    """A named upstream: an OpenAI-compatible base URL and an optional key."""

    name: str
    url: str
    api_key: SecretStr | None = None

    def auth_headers(self) -> dict[str, str]:
        """``Authorization: Bearer <key>`` when the route has a key."""
        if self.api_key is None:
            return {}
        return {"Authorization": f"Bearer {self.api_key.get_secret_value()}"}


@dataclass(frozen=True)
class GatewayUpstreams:
    """The routes of the gateway and the name of the default one."""

    routes: Mapping[str, GatewayUpstream]
    default: str

    @classmethod
    def single(cls, url: str, api_key: SecretStr | None = None) -> GatewayUpstreams:
        """One route, named ``default``, to *url*."""
        route = GatewayUpstream(SINGLE_ROUTE_NAME, url.rstrip("/"), api_key)
        return cls(routes={SINGLE_ROUTE_NAME: route}, default=SINGLE_ROUTE_NAME)

    def names(self) -> list[str]:
        """Route names, in configuration order."""
        return list(self.routes)

    def select(self, name: str) -> GatewayUpstream | None:
        """The route called *name*, the default route when *name* is empty,
        or None when no route has that name."""
        return self.routes.get(name or self.default)


def build_gateway_upstreams(
    settings: Any,
    gateway: GatewayConfig | None = None,
    environ: Mapping[str, str] | None = None,
) -> GatewayUpstreams:
    """Resolve the gateway routes and their keys, reading key files once.

    Args:
        settings: Proxy settings (``ADMINA_GATEWAY_UPSTREAM``,
            ``ADMINA_GATEWAY_UPSTREAMS``, ``ADMINA_GATEWAY_UPSTREAM_API_KEY``
            and ``ADMINA_GATEWAY_UPSTREAM_API_KEY_FILE``).
        gateway: The ``gateway`` section of ``admina.yaml``, if any.
        environ: Where the per-route key variables are looked up;
            defaults to the process environment over the ``.env`` file
            of *settings*, the precedence of the settings fields.

    Raises:
        GatewayUpstreamError: A route, the default route or a key is
            misconfigured, or a key file cannot be used.
    """
    environ = settings_environment(settings) if environ is None else environ
    gateway = gateway or GatewayConfig()
    if gateway.errors:
        raise GatewayUpstreamError("; ".join(gateway.errors))

    default_key = _key(
        _plain(getattr(settings, _DEFAULT_KEY_SETTING, "")),
        getattr(settings, f"{_DEFAULT_KEY_SETTING}_FILE", ""),
        _DEFAULT_KEY_SETTING,
    )

    env_routes = str(getattr(settings, _ROUTES_SETTING, "") or "").strip()
    if env_routes:
        table = _check_routes(_parse_routes(env_routes), _ROUTES_SETTING)
        key_files: dict[str, str] = {}
    elif gateway.upstreams:
        table = _check_routes(
            [(name, entry.url.strip()) for name, entry in gateway.upstreams.items()],
            "gateway.upstreams",
        )
        key_files = {name: entry.api_key_file for name, entry in gateway.upstreams.items()}
    else:
        table = [(SINGLE_ROUTE_NAME, settings.ADMINA_GATEWAY_UPSTREAM)]
        key_files = {}

    routes: dict[str, GatewayUpstream] = {}
    for name, url in table:
        api_key = _route_key(name, key_files.get(name, ""), environ) or default_key
        routes[name] = GatewayUpstream(name, url.rstrip("/"), api_key)

    default = gateway.default_upstream or next(iter(routes))
    if default not in routes:
        raise GatewayUpstreamError(
            f"gateway.default_upstream names {default!r}, which is not a configured route"
        )
    return GatewayUpstreams(routes=routes, default=default)


def settings_environment(settings: Any) -> dict[str, str]:
    """The process environment over the ``.env`` file of *settings*, as the
    settings read them."""
    config = getattr(settings, "model_config", None) or {}
    env_file = config.get("env_file")
    values: dict[str, str] = {}
    if isinstance(env_file, str | os.PathLike) and os.path.isfile(env_file):
        from dotenv import dotenv_values

        encoding = config.get("env_file_encoding") or "utf-8"
        loaded = dotenv_values(env_file, encoding=encoding)
        values = {name: value for name, value in loaded.items() if value is not None}
    return {**values, **os.environ}


def _parse_routes(value: str) -> list[tuple[str, str]]:
    """Split ``name=url[,name=url…]``; empty items are skipped."""
    table: list[tuple[str, str]] = []
    for position, item in enumerate(value.split(","), start=1):
        if not item.strip():
            continue
        name, sep, url = item.partition("=")
        if not sep:
            raise GatewayUpstreamError(f"{_ROUTES_SETTING}: entry {position} is not name=url")
        table.append((name.strip(), url.strip()))
    return table


def _check_routes(table: list[tuple[str, str]], source: str) -> list[tuple[str, str]]:
    """Check route names, their uniqueness and URLs; return *table*."""
    seen: set[str] = set()
    for name, url in table:
        if not _ROUTE_NAME.fullmatch(name):
            raise GatewayUpstreamError(
                f"{source}: route name {name!r} is not valid "
                "(use 1 to 64 lowercase letters, digits or underscores)"
            )
        if name in seen:
            raise GatewayUpstreamError(f"{source}: route {name!r} is defined twice")
        seen.add(name)
        if not _is_http_url(url):
            raise GatewayUpstreamError(
                f"{source}: route {name!r} needs an http:// or https:// URL with a host"
            )
    return table


def _is_http_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return parts.scheme in ("http", "https") and bool(parts.hostname)
    except ValueError:  # e.g. an unbalanced IPv6 bracket
        return False


def _route_key(name: str, key_file: str, environ: Mapping[str, str]) -> SecretStr | None:
    setting = f"ADMINA_GATEWAY_UPSTREAM_{name.upper()}_API_KEY"
    key = _key(environ.get(setting), environ.get(f"{setting}_FILE"), setting)
    if key is None and key_file:
        key = _key_from_file(key_file, f"gateway.upstreams.{name}.api_key_file")
    return key


def _key(value: str | None, file_path: str | None, setting: str) -> SecretStr | None:
    """The key given as *setting* or in the file named by ``<setting>_FILE``."""
    try:
        key = resolve_secret(value, file_path, setting=setting)
    except SecretFileError as exc:
        raise GatewayUpstreamError(str(exc)) from None
    if key is None:
        return None
    return _checked(key, f"{setting}_FILE" if file_path else setting)


def _key_from_file(path: str, setting: str) -> SecretStr:
    try:
        key = read_secret_file(path, setting=setting)
    except SecretFileError as exc:
        raise GatewayUpstreamError(str(exc)) from None
    return _checked(key, setting)


def _checked(key: str, source: str) -> SecretStr:
    if not _KEY_CHARS.fullmatch(key):
        raise GatewayUpstreamError(
            f"{source}: the key must be printable ASCII without spaces or control characters"
        )
    return SecretStr(key)


def _plain(value: Any) -> str:
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    return value or ""

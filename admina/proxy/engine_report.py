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

"""Admina — the running engines in the startup banner and on ``/metrics``.

Both are built from :func:`admina.engines.engine_status` of the engines the
proxy built (``firewall``, ``loop_breaker``, ``pii``), the ``admina-core``
version, and the settings that switch the firewall
(``INJECTION_FAST_PATH_ENABLED``) and PII redaction
(``PII_REDACTION_ENABLED``) on the gateway and ``/mcp``.
"""

from __future__ import annotations

from typing import Any

__all__ = ["engine_banner", "engine_info_lines"]


def engine_banner(status: dict[str, Any], *, firewall_on: bool, pii_on: bool) -> list[str]:
    """The two banner lines of the engines: ``Engine selection:
    ADMINA_ENGINE=auto (admina-core 0.13.0)`` and ``Firewall: ON (rust
    engine) | PII Redaction: OFF (gateway and /mcp) | Loop Breaker: OFF``.
    *firewall_on* and *pii_on* are the settings that switch the firewall and
    PII redaction on the gateway and ``/mcp``."""
    core = (
        f"admina-core {status['rust_version']}"
        if status.get("rust_version")
        else "admina-core not installed"
    )
    loop_breaker = status.get("loop_breaker")
    return [
        f"  Engine selection: ADMINA_ENGINE={status.get('selection')} ({core})",
        f"  Firewall: {_on_off(firewall_on, status.get('firewall'))} | "
        f"PII Redaction: {_on_off(pii_on, status.get('pii'))} | "
        f"Loop Breaker: {f'ON ({loop_breaker} engine)' if loop_breaker else 'OFF'}",
    ]


def _on_off(on: bool, engine: str | None) -> str:
    return f"ON ({engine} engine)" if on else "OFF (gateway and /mcp)"


def engine_info_lines(status: dict[str, Any], *, pii_on: bool, version: str) -> list[str]:
    """The ``admina_engine_info`` gauge (value 1): ``engine`` and
    ``firewall`` (the firewall's engine), ``loop_breaker`` (``none`` when
    none is built), ``pii`` (the PII engine), ``pii_redaction``
    (``on``/``off``), ``rust_available`` (``yes``/``no``), ``rust_version``
    (the ``admina-core`` version, empty without it), ``selection``
    (``ADMINA_ENGINE``) and ``version`` (Admina's)."""
    labels = {
        "engine": status.get("firewall") or "none",
        "firewall": status.get("firewall") or "none",
        "loop_breaker": status.get("loop_breaker") or "none",
        "pii": status.get("pii") or "none",
        "pii_redaction": "on" if pii_on else "off",
        "rust_available": "yes" if status.get("rust_available") else "no",
        "rust_version": status.get("rust_version") or "",
        "selection": status.get("selection") or "",
        "version": version,
    }
    rendered = ",".join(f'{name}="{_escape(value)}"' for name, value in labels.items())
    return [
        "# HELP admina_engine_info The engines the proxy runs",
        "# TYPE admina_engine_info gauge",
        f"admina_engine_info{{{rendered}}} 1",
    ]


def _escape(value: str) -> str:
    """A Prometheus label value: backslash, double quote and line feed escaped."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

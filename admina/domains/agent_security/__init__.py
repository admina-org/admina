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

"""Admina — Agent Security Domain.

Loop breaker, anti-injection firewall, and governance proxy.

LoopBreaker depends on ``numpy`` and ``scikit-learn`` (the ``[nlp]``
extra) and is loaded lazily via PEP 562 ``__getattr__`` so importing
this package never fails on a pure-SDK install.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from admina.domains.agent_security.firewall import InjectionFirewall

if TYPE_CHECKING:  # pragma: no cover
    from admina.domains.agent_security.loop_breaker import LoopBreaker

__all__ = ["LoopBreaker", "InjectionFirewall"]


def __getattr__(name: str):
    if name == "LoopBreaker":
        from admina.domains.agent_security.loop_breaker import LoopBreaker

        return LoopBreaker
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

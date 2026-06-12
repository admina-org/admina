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

"""Deprecated location — the engine bridge moved to :mod:`admina.engines`.

This shim re-exports the public surface so pre-0.10 imports keep working.
"""

from __future__ import annotations

from admina.engines import (
    ENGINE,
    FirewallBridge,
    LoopBreakerBridge,
    PIIBridge,
    engine_status,
    get_firewall,
    get_loop_breaker,
    get_pii_engine,
    get_pii_scanner,
)

__all__ = [
    "ENGINE",
    "FirewallBridge",
    "LoopBreakerBridge",
    "PIIBridge",
    "engine_status",
    "get_firewall",
    "get_loop_breaker",
    "get_pii_engine",
    "get_pii_scanner",
]

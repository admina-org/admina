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

"""Shared lazy-loaded governance engines for integration callbacks.

Thread-safe via module-level lock. Engines are created once on first use.
Engines are acquired from :mod:`admina.engines`, which handles Rust
auto-detection, ``ADMINA_ENGINE`` override, admina.yaml firewall overrides,
and ``pii_engine`` selection.
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_firewall = None
_pii_redactor = None
_loop_breaker = None


def get_firewall():
    """Return the shared firewall engine (via admina.engines)."""
    global _firewall
    if _firewall is None:
        with _lock:
            if _firewall is None:
                from admina.engines import get_firewall as _get_fw

                _firewall = _get_fw()
    return _firewall


def get_pii_redactor():
    """Return the shared PII engine (via admina.engines)."""
    global _pii_redactor
    if _pii_redactor is None:
        with _lock:
            if _pii_redactor is None:
                from admina.engines import get_pii_engine as _get_pii

                _pii_redactor = _get_pii()
    return _pii_redactor


def get_loop_breaker():
    """Return the shared loop breaker engine (via admina.engines)."""
    global _loop_breaker
    if _loop_breaker is None:
        with _lock:
            if _loop_breaker is None:
                from admina.engines import get_loop_breaker as _get_lb

                _loop_breaker = _get_lb()
    return _loop_breaker

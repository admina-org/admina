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
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_firewall = None
_pii_redactor = None
_loop_breaker = None


def get_firewall():
    """Return the shared InjectionFirewall instance."""
    global _firewall
    if _firewall is None:
        with _lock:
            if _firewall is None:
                from admina.domains.agent_security.firewall import InjectionFirewall

                _firewall = InjectionFirewall()
    return _firewall


def get_pii_redactor():
    """Return the shared PIIRedactor instance."""
    global _pii_redactor
    if _pii_redactor is None:
        with _lock:
            if _pii_redactor is None:
                from admina.domains.data_sovereignty.pii import PIIRedactor

                _pii_redactor = PIIRedactor()
    return _pii_redactor


def get_loop_breaker():
    """Return the shared LoopBreaker instance."""
    global _loop_breaker
    if _loop_breaker is None:
        with _lock:
            if _loop_breaker is None:
                from admina.domains.agent_security.loop_breaker import LoopBreaker

                _loop_breaker = LoopBreaker()
    return _loop_breaker

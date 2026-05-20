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

"""
Admina — Hybrid Engine Bridge
Auto-detects Rust engine, falls back to pure Python.
"""

from __future__ import annotations

import logging
from datetime import UTC
from typing import Any, Protocol

logger = logging.getLogger("admina.engine")

# ── Detect Rust engine ──────────────────────────────────────
ENGINE = "python"
_rust_available = False

try:
    import admina_core

    _rust_available = True
    ENGINE = "rust"
    _info = admina_core.engine_info()
    logger.info(
        "[RUST] Rust engine loaded: v%s — modules: %s", admina_core.version(), _info["modules"]
    )
except ImportError:
    logger.info(
        "[PYTHON] Rust engine not found, using pure Python (install admina-core for 10-100x speedup)"
    )


# ── Firewall Bridge ─────────────────────────────────────────
def _load_firewall_yaml_overrides() -> tuple[list, list]:
    """Read agent_security.firewall.{custom_patterns,disabled_categories}
    from admina.yaml if present. Falls back to no overrides on any error.
    Each custom pattern in YAML is `{regex, category, risk_level}`.
    """
    extras: list = []
    disabled: list = []
    try:
        from admina.core.config import load_config
        from admina.core.types import RiskLevel

        cfg = load_config()
        fw_cfg = (
            cfg.raw.get("domains", {}).get("agent_security", {}).get("firewall", {})
            if hasattr(cfg, "raw") and isinstance(cfg.raw, dict)
            else {}
        )
        disabled = list(fw_cfg.get("disabled_categories") or [])
        for entry in fw_cfg.get("custom_patterns") or []:
            try:
                extras.append(
                    (
                        entry["regex"],
                        entry.get("category", "user_custom"),
                        RiskLevel(entry.get("risk_level", "medium").lower()),
                    )
                )
            except (KeyError, ValueError, TypeError) as exc:
                logger.warning("Skipping malformed custom_pattern %r: %s", entry, exc)
    except (ImportError, AttributeError, OSError):
        pass
    return extras, disabled


class _PythonFirewallBridge:
    """Wraps the existing Python InjectionFirewall with a compatible interface."""

    def __init__(self):
        from admina.domains.agent_security.firewall import InjectionFirewall

        extras, disabled = _load_firewall_yaml_overrides()
        if extras or disabled:
            logger.info(
                "Loaded %d custom firewall pattern(s); disabled: %s",
                len(extras),
                disabled or "(none)",
            )
        self._impl = InjectionFirewall(
            extra_patterns=extras or None,
            disabled_categories=disabled or None,
        )

    def check(self, text: str) -> dict:
        return self._impl.check(text)

    def get_stats(self) -> dict:
        stats = self._impl.get_stats()
        stats["engine"] = "python"
        return stats


class _RustFirewallBridge:
    """Wraps Rust RustFirewall, returns dicts for compatibility."""

    def __init__(self):
        self._impl = admina_core.RustFirewall()

    def check(self, text: str) -> dict:
        result = self._impl.check(text)
        return {
            "is_injection": result.is_injection,
            "risk_level": result.risk_level,
            "matched_patterns": result.matched_patterns,
            "heuristic_score": result.heuristic_score,
            "heuristic_signals": result.heuristic_signals,
        }

    def get_stats(self) -> dict:
        return self._impl.get_stats()


# ── PII Scanner Bridge ──────────────────────────────────────
class _PythonPiiBridge:
    def __init__(self):
        from admina.domains.data_sovereignty.pii import PIIRedactor

        self._impl = PIIRedactor()

    def redact(self, text: str) -> dict:
        return self._impl.redact(text)

    def get_stats(self) -> dict:
        stats = self._impl.get_stats()
        stats["engine"] = "python"
        return stats


class _RustPiiBridge:
    def __init__(self):
        self._impl = admina_core.RustPiiScanner()

    def redact(self, text: str) -> dict:
        result = self._impl.redact(text)
        return {
            "redacted_text": result.redacted_text,
            "count": result.count,
            "categories": result.categories,
            "entities": [{"type": cat, "method": "rust_regex"} for cat in result.categories],
        }

    def get_stats(self) -> dict:
        return self._impl.get_stats()


# ── Loop Breaker Bridge ─────────────────────────────────────
class _PythonLoopBridge:
    def __init__(self, **kwargs):
        from admina.domains.agent_security.loop_breaker import LoopBreaker

        self._impl = LoopBreaker(**kwargs)

    def check(self, session_id: str, content: str) -> dict:
        return self._impl.check(session_id, content)

    def get_stats(self) -> dict:
        stats = self._impl.get_stats()
        stats["engine"] = "python"
        return stats


class _RustLoopBridge:
    def __init__(self, window_size=10, similarity_threshold=0.85, max_consecutive=3, **kwargs):
        self._impl = admina_core.RustLoopBreaker(
            window_size=window_size,
            similarity_threshold=similarity_threshold,
            max_consecutive=max_consecutive,
        )

    def check(self, session_id: str, content: str) -> dict:
        return self._impl.check(session_id, content)

    def get_stats(self) -> dict:
        return self._impl.get_stats()


# ── Hash Chain Bridge ────────────────────────────────────────
class _PythonHashChainBridge:
    def __init__(self):
        # Minimal Python fallback
        self._prev = "genesis"
        self._seq = 0
        self._total = 0

    def record(self, event_id: str, data: str) -> dict:
        import hashlib
        from datetime import datetime

        self._seq += 1
        self._total += 1
        now = datetime.now(UTC)
        hash_input = f"{self._seq}:{self._prev}:{event_id}:{data}:{int(now.timestamp() * 1000)}"
        h = hashlib.sha256(hash_input.encode()).hexdigest()
        prev = self._prev
        self._prev = h
        return {
            "hash": h,
            "previous_hash": prev,
            "sequence": self._seq,
            "event_id": event_id,
            "timestamp_iso": now.isoformat(),
            "timestamp_ms": int(now.timestamp() * 1000),
            "engine": "python",
        }

    def get_stats(self) -> dict:
        return {"total_records": self._total, "current_sequence": self._seq, "engine": "python"}


class _RustHashChainBridge:
    def __init__(self):
        self._impl = admina_core.RustHashChain()

    def record(self, event_id: str, data: str) -> dict:
        return self._impl.record(event_id, data)

    def verify_chain(self, chain: list) -> dict[str, Any]:
        return self._impl.verify_chain(chain)

    def get_stats(self) -> dict:
        return self._impl.get_stats()


# ── Bridge Protocols ────────────────────────────────────────


class FirewallBridge(Protocol):
    """Protocol for firewall bridge implementations."""

    def check(self, text: str) -> dict[str, Any]: ...
    def get_stats(self) -> dict[str, Any]: ...


class PIIBridge(Protocol):
    """Protocol for PII scanner bridge implementations."""

    def redact(self, text: str) -> dict[str, Any]: ...
    def get_stats(self) -> dict[str, Any]: ...


class LoopBreakerBridge(Protocol):
    """Protocol for loop breaker bridge implementations."""

    def check(self, session_id: str, content: str) -> dict[str, Any]: ...
    def get_stats(self) -> dict[str, Any]: ...


class HashChainBridge(Protocol):
    """Protocol for hash chain bridge implementations."""

    def record(self, event_id: str, data: str) -> dict[str, Any]: ...
    def get_stats(self) -> dict[str, Any]: ...


# ── Factory Functions ────────────────────────────────────────
def get_firewall() -> FirewallBridge:
    """Get the best available firewall engine."""
    if _rust_available:
        return _RustFirewallBridge()
    return _PythonFirewallBridge()


def get_pii_scanner() -> PIIBridge:
    """Get the best available PII scanner."""
    if _rust_available:
        return _RustPiiBridge()
    return _PythonPiiBridge()


def get_loop_breaker(**kwargs: Any) -> LoopBreakerBridge:
    """Get the best available loop breaker."""
    if _rust_available:
        return _RustLoopBridge(**kwargs)
    return _PythonLoopBridge(**kwargs)


def get_hash_chain() -> HashChainBridge:
    """Get the best available hash chain."""
    if _rust_available:
        return _RustHashChainBridge()
    return _PythonHashChainBridge()


def engine_status() -> dict[str, Any]:
    """Get engine status for diagnostics."""
    return {
        "engine": ENGINE,
        "rust_available": _rust_available,
        "rust_version": admina_core.version() if _rust_available else None,
    }

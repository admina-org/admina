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

"""Admina — unified engine acquisition.

Single point where every surface (proxy, SDK, integrations) obtains the
governance engines: Rust auto-detection, ``ADMINA_ENGINE=auto|python|rust``
override, admina.yaml firewall overrides, ``pii_engine`` selection.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Protocol

logger = logging.getLogger("admina.engines")

# ── Detect Rust engine ──────────────────────────────────────────────────────
ENGINE = "python"
_rust_available = False

try:
    import admina_core  # type: ignore[import-untyped]

    _rust_available = True
    ENGINE = "rust"
    _info = admina_core.engine_info()
    logger.info(
        "[RUST] Rust engine loaded: v%s — modules: %s",
        admina_core.version(),
        _info["modules"],
    )
except ImportError:
    logger.info(
        "[PYTHON] Rust engine not found, using pure Python "
        "(install admina-core for 10-100x speedup)"
    )


# ── Engine selector ─────────────────────────────────────────────────────────

def _resolve_engine() -> str:
    """Return the effective engine name based on ADMINA_ENGINE env override.

    Returns ``"rust"`` or ``"python"``.

    Raises:
        ValueError: if ``ADMINA_ENGINE`` is set to an unrecognised value.
    """
    mode = os.environ.get("ADMINA_ENGINE", "auto").lower()
    if mode not in ("auto", "python", "rust"):
        raise ValueError(
            f"ADMINA_ENGINE must be auto|python|rust, got {mode!r}"
        )
    if mode == "rust" and not _rust_available:
        logger.warning(
            "ADMINA_ENGINE=rust but admina-core is not installed — "
            "falling back to python (pip install 'admina-framework[rust]')"
        )
        return "python"
    if mode == "auto":
        return "rust" if _rust_available else "python"
    return mode


# ── Firewall YAML overrides ─────────────────────────────────────────────────

def _load_firewall_yaml_overrides() -> tuple[list, list]:
    """Read agent_security.firewall.{custom_patterns,disabled_categories}
    from admina.yaml if present. Falls back to no overrides on any error.
    Each custom pattern in YAML is ``{regex, category, risk_level}``.
    """
    extras: list = []
    disabled: list = []
    try:
        from admina.core.config import load_config
        from admina.core.types import RiskLevel

        fw_cfg = load_config().agent_security.firewall
        disabled = list(fw_cfg.disabled_categories)
        for entry in fw_cfg.custom_patterns:
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
    except (ImportError, AttributeError, OSError) as exc:
        logger.debug("Firewall YAML overrides unavailable: %s", exc)
    return extras, disabled


# ── Bridge Protocols ────────────────────────────────────────────────────────

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


# ── Firewall bridges ────────────────────────────────────────────────────────

class _PythonFirewallBridge:
    """Wraps the existing Python InjectionFirewall with a compatible interface."""

    def __init__(self, extras: list | None = None, disabled: list | None = None):
        from admina.domains.agent_security.firewall import InjectionFirewall

        if extras is None and disabled is None:
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
    """Wraps Rust RustFirewall, returns dicts for compatibility.

    Stats normalization: Rust tracks ``checks_total``/``injections_detected``
    with no per-type breakdown; mapped to the Python key set.
    """

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
        raw = self._impl.get_stats()
        checks_total = raw.get("checks_total", 0)
        injections_detected = raw.get("injections_detected", 0)
        return {
            "total_checked": checks_total,
            "total_blocked": injections_detected,
            "block_rate": round(injections_detected / max(checks_total, 1) * 100, 2),
            # Rust does not track detections per category — empty dict placeholder
            "detections_by_type": {},
            "engine": "rust",
        }


# ── PII scanner bridges ─────────────────────────────────────────────────────

class _PythonPiiBridge:
    """Wraps the Python PIIRedactor."""

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
    """Wraps Rust RustPiiScanner, returns dicts for compatibility.

    Stats normalization: Rust tracks ``total_scans``/``total_redactions``
    with no per-type breakdown; mapped to the Python key set.
    """

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
        raw = self._impl.get_stats()
        return {
            # total_redactions = cumulative entity count — same semantics as Python PIIRedactor.total_redacted
            "total_redacted": raw.get("total_redactions", 0),
            # Rust does not track redactions per category — empty dict placeholder
            "redactions_by_type": {},
            # Rust does not use spaCy — False by definition
            "spacy_available": False,
            "engine": "rust",
        }


# ── Loop breaker bridges ────────────────────────────────────────────────────

class _PythonLoopBridge:
    """Wraps the Python LoopBreaker."""

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
    """Wraps Rust RustLoopBreaker, returns dicts for compatibility.

    Stats normalization: Rust tracks additional keys (window_size,
    similarity_threshold, total_checks) beyond the Python key set;
    mapped to the Python key set only.
    """

    def __init__(self, window_size=10, similarity_threshold=0.85, max_consecutive=3, **kwargs):
        self._impl = admina_core.RustLoopBreaker(
            window_size=window_size,
            similarity_threshold=similarity_threshold,
            max_consecutive=max_consecutive,
        )

    def check(self, session_id: str, content: str) -> dict:
        return self._impl.check(session_id, content)

    def get_stats(self) -> dict:
        raw = self._impl.get_stats()
        return {
            "active_sessions": raw.get("active_sessions", 0),
            # Rust calls this "loops_detected"; Python calls it "total_blocked"
            "total_blocked": raw.get("loops_detected", 0),
            "engine": "rust",
        }


# ── Factory functions ───────────────────────────────────────────────────────

def get_firewall() -> FirewallBridge:
    """Get the configured firewall engine.

    If YAML overrides (custom_patterns or disabled_categories) are present,
    the Python bridge is used even when Rust is available — Rust cannot
    receive operator-defined patterns, so using it would silently ignore them.
    """
    extras, disabled = _load_firewall_yaml_overrides()
    if extras or disabled:
        resolved = _resolve_engine()
        if resolved == "rust":
            logger.warning(
                "YAML firewall overrides (custom_patterns/disabled_categories) are set "
                "but the Rust engine cannot apply them — falling back to the Python bridge "
                "so operator rules are enforced. Remove overrides to use Rust acceleration."
            )
        return _PythonFirewallBridge(extras=extras, disabled=disabled)
    if _resolve_engine() == "rust":
        return _RustFirewallBridge()
    return _PythonFirewallBridge()


def get_loop_breaker(**kwargs: Any) -> LoopBreakerBridge:
    """Get the configured loop breaker."""
    if _resolve_engine() == "rust":
        return _RustLoopBridge(**kwargs)
    return _PythonLoopBridge(**kwargs)


# ── PII engine registry and resolver ───────────────────────────────────────

_PII_ENGINE_FACTORIES: dict[str, Callable[[], PIIBridge]] = {}


def _spacy_regex_pii() -> PIIBridge:
    if _resolve_engine() == "rust":
        return _RustPiiBridge()
    return _PythonPiiBridge()


_PII_ENGINE_FACTORIES["spacy-regex"] = _spacy_regex_pii


def get_pii_engine(name: str | None = None) -> PIIBridge:
    """Get the configured PII engine.

    Resolution order: explicit *name* arg > admina.yaml ``pii_engine`` >
    ``spacy-regex``. An engine selected by name takes precedence over
    Rust auto-detection (Rust accelerates only the ``spacy-regex`` path).
    """
    if name is None:
        try:
            from admina.core.config import load_config

            name = load_config().pii_engine
        except (ImportError, ValueError, OSError) as exc:
            logger.debug("pii_engine config unavailable, defaulting to spacy-regex: %s", exc)
            name = "spacy-regex"
    factory = _PII_ENGINE_FACTORIES.get(name)
    if factory is None:
        raise ValueError(
            f"Unknown pii_engine {name!r}. Available: "
            f"{sorted(_PII_ENGINE_FACTORIES)}. 'presidio' requires "
            f"admina-framework[presidio] (0.10+)."
        )
    return factory()


def get_pii_scanner() -> PIIBridge:
    """Deprecated alias for :func:`get_pii_engine` (proxy bridge name)."""
    return get_pii_engine()


# ── Status / diagnostics ────────────────────────────────────────────────────

def engine_status() -> dict[str, Any]:
    """Get engine status for diagnostics."""
    return {
        "engine": ENGINE,
        "rust_available": _rust_available,
        "rust_version": admina_core.version() if _rust_available else None,
        "selection": os.environ.get("ADMINA_ENGINE", "auto"),
        "active": _resolve_engine(),
    }


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

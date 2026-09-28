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
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from admina.core.offline import apply_offline_environment
from admina.engines.pii_plugins import PIIEngineBridge, load_plugin_engine, plugin_engine_names

if TYPE_CHECKING:
    from admina.core.config import AdminaConfig, FirewallConfig
    from admina.domains.agent_security.egress import EgressPolicy
    from admina.domains.agent_security.pattern_packs import PatternPack

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
        raise ValueError(f"ADMINA_ENGINE must be auto|python|rust, got {mode!r}")
    if mode == "rust" and not _rust_available:
        logger.warning(
            "ADMINA_ENGINE=rust but admina-core is not installed — "
            "falling back to python (pip install 'admina-framework[rust]')"
        )
        return "python"
    if mode == "auto":
        return "rust" if _rust_available else "python"
    return mode


def _resolve_pii_engine() -> str:
    """Resolve the engine backing the spacy-regex PII path.

    Recall-safe policy: the Rust PII scanner does NOT cover EU national
    IDs (codice fiscale / DNI / Personalausweis) or NER person/org names
    that the Python engine redacts. To avoid silently under-redacting,
    Rust PII is used only when ADMINA_ENGINE=rust is set explicitly;
    under 'auto' (the default) the PII path stays on Python for full
    recall. Firewall and loop breaker are unaffected — they use
    _resolve_engine() and keep Rust acceleration under 'auto'.
    """
    mode = os.environ.get("ADMINA_ENGINE", "auto").lower()
    if mode not in ("auto", "python", "rust"):
        raise ValueError(f"ADMINA_ENGINE must be auto|python|rust, got {mode!r}")
    if mode == "rust":
        if not _rust_available:
            logger.warning(
                "ADMINA_ENGINE=rust but admina-core is not installed — "
                "PII falls back to python (pip install 'admina-framework[rust]')"
            )
            return "python"
        return "rust"
    if mode == "auto" and _rust_available:
        logger.debug(
            "PII engine stays on Python under ADMINA_ENGINE=auto for full "
            "recall (EU national IDs + NER); set ADMINA_ENGINE=rust to "
            "use the faster Rust scanner (lower PII recall)"
        )
    return "python"


# ── Firewall YAML overrides ─────────────────────────────────────────────────


def _firewall_config() -> FirewallConfig | None:
    """``agent_security.firewall`` of admina.yaml (or of the .env fallback);
    None when the file cannot be read, except for a file named by
    ``ADMINA_CONFIG``, whose failure raises
    :class:`~admina.core.config.ConfigFileError`."""
    try:
        from admina.core.config import load_config

        return load_config().agent_security.firewall
    except (ImportError, AttributeError, OSError) as exc:
        logger.debug("Firewall YAML overrides unavailable: %s", exc)
        return None


def _custom_patterns(fw_cfg: FirewallConfig) -> list:
    from admina.domains.agent_security.firewall import parse_custom_patterns

    return parse_custom_patterns(
        fw_cfg.custom_patterns,
        on_error=lambda entry, exc: logger.warning(
            "Skipping malformed custom_pattern %r: %s", entry, exc
        ),
    )


def _load_firewall_yaml_overrides() -> tuple[list, list]:
    """Read agent_security.firewall.{custom_patterns,disabled_categories}
    from admina.yaml if present. Falls back to no overrides when the file
    cannot be read, except for a file named by ``ADMINA_CONFIG``, whose
    failure raises :class:`~admina.core.config.ConfigFileError`.
    Each custom pattern in YAML is ``{regex, category, risk_level}``.
    """
    fw_cfg = _firewall_config()
    if fw_cfg is None:
        return [], []
    return _custom_patterns(fw_cfg), list(fw_cfg.disabled_categories)


@dataclass(frozen=True)
class _FirewallSettings:
    """The firewall settings of admina.yaml that the Python firewall applies."""

    extras: list = field(default_factory=list)
    disabled_categories: list[str] = field(default_factory=list)
    disabled_patterns: list[str] = field(default_factory=list)
    packs: tuple[PatternPack, ...] = ()
    heuristic_threshold: float = 0.5
    allowed_tags: list[str] = field(default_factory=list)

    @property
    def python_only(self) -> bool:
        """True when a setting only the Python firewall applies is set."""
        return bool(self.extras or self.disabled_categories or self.disabled_patterns or self.packs)


def _firewall_settings() -> _FirewallSettings:
    """The :class:`_FirewallSettings` of admina.yaml (none when the file
    cannot be read, as :func:`_firewall_config`), with its pattern packs
    loaded and timed.

    Raises:
        PatternPackError: a pattern pack cannot be loaded, or is too slow
            with ``strict_pack_timing``.
    """
    from admina.domains.agent_security.pattern_packs import configured_packs

    fw_cfg = _firewall_config()
    if fw_cfg is None:
        return _FirewallSettings()
    return _FirewallSettings(
        extras=_custom_patterns(fw_cfg),
        disabled_categories=list(fw_cfg.disabled_categories),
        disabled_patterns=list(fw_cfg.disabled_patterns),
        packs=tuple(configured_packs(fw_cfg)),
        heuristic_threshold=fw_cfg.heuristic_threshold,
        allowed_tags=list(fw_cfg.allowed_tags),
    )


#: Environment variable that turns the firewall's deep path off.
DEEP_PATH_ENV = "INJECTION_DEEP_PATH_ENABLED"
_FALSE_WORDS = frozenset({"0", "false", "no", "off", "f", "n"})


def _deep_path_from_env() -> bool:
    """``INJECTION_DEEP_PATH_ENABLED``: False for 0, false, f, no, n, off
    (any case, as the proxy settings read it); True otherwise, and when
    unset or empty."""
    return os.environ.get(DEEP_PATH_ENV, "").strip().lower() not in _FALSE_WORDS


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

    engine = "python"

    def __init__(
        self, settings: _FirewallSettings | None = None, *, deep_path_enabled: bool = True
    ):
        from admina.domains.agent_security.firewall import InjectionFirewall

        if settings is None:
            settings = _firewall_settings()
        if settings.python_only:
            logger.info(
                "Loaded %d custom firewall pattern(s); pattern packs: %s; "
                "disabled categories: %s; disabled patterns: %s",
                len(settings.extras),
                ", ".join(f"{p.name} {p.version}" for p in settings.packs) or "(none)",
                settings.disabled_categories or "(none)",
                settings.disabled_patterns or "(none)",
            )
        self._impl = InjectionFirewall(
            extra_patterns=settings.extras or None,
            disabled_categories=settings.disabled_categories or None,
            disabled_patterns=settings.disabled_patterns,
            pattern_packs=settings.packs,
            heuristic_threshold=settings.heuristic_threshold,
            allowed_tags=settings.allowed_tags,
            deep_path_enabled=deep_path_enabled,
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

    engine = "rust"

    def __init__(self, *, deep_path_enabled: bool = True):
        self._impl = admina_core.RustFirewall(deep_path=deep_path_enabled)

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

    def __init__(self, mask_style: str = "typed"):
        from admina.domains.data_sovereignty.pii import PIIRedactor

        self._impl = PIIRedactor(mask_style=mask_style)

    def redact(self, text: str) -> dict:
        return self._impl.redact(text)

    def get_stats(self) -> dict:
        stats = self._impl.get_stats()
        stats["engine"] = "python"
        return stats


class _RustPiiBridge:
    """Wraps Rust RustPiiScanner, returns dicts for compatibility.

    Stats normalization: Rust tracks ``total_scans``/``total_redactions``
    with no per-type breakdown; mapped to the Python key set. In the
    ``omissis`` mask style the scanner's masks (``[EMAIL_REDACTED]``, …)
    become ``[OMISSIS]``.
    """

    def __init__(self, mask_style: str = "typed"):
        from admina.domains.data_sovereignty.masking import normalize_mask_style

        self._impl = admina_core.RustPiiScanner()
        self._omissis = normalize_mask_style(mask_style) == "omissis"

    def redact(self, text: str) -> dict:
        result = self._impl.redact(text)
        redacted = result.redacted_text
        if self._omissis and result.count:
            from admina.domains.data_sovereignty.masking import OMISSIS

            redacted = _RUST_PII_MASK_RX.sub(OMISSIS, redacted)
        return {
            "redacted_text": redacted,
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


# Masks of the Rust PII scanner (admina_core).
_RUST_PII_MASK_RX = re.compile(r"\[(?:EMAIL|CC|SSN|PHONE|IBAN|IP)_REDACTED\]")


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


def get_firewall(*, deep_path_enabled: bool | None = None) -> FirewallBridge:
    """Get the configured firewall engine.

    If YAML overrides (custom_patterns, disabled_categories,
    disabled_patterns or pattern_packs) are present, the Python bridge is
    used even when Rust is available — Rust cannot receive operator-defined
    patterns, so using it would silently ignore them.

    *deep_path_enabled* switches the deep path (heuristic scoring) of either
    engine; ``None`` reads ``INJECTION_DEEP_PATH_ENABLED`` (default on).
    ``heuristic_threshold`` and ``allowed_tags`` apply to the Python
    firewall; the Rust engine scores with signals and a threshold of its own.

    Raises:
        ValueError: ``heuristic_threshold`` is not a finite number greater
            than 0; a pattern pack cannot be loaded, or is too slow with
            ``strict_pack_timing``
            (:class:`~admina.domains.agent_security.pattern_packs.PatternPackError`).
    """
    if deep_path_enabled is None:
        deep_path_enabled = _deep_path_from_env()
    settings = _firewall_settings()
    if settings.python_only:
        resolved = _resolve_engine()
        if resolved == "rust":
            logger.warning(
                "YAML firewall overrides (custom_patterns/disabled_categories/"
                "disabled_patterns/pattern_packs) are set but the Rust engine cannot apply them — "
                "falling back to the Python bridge so operator rules are enforced. "
                "Remove overrides to use Rust acceleration."
            )
        return _PythonFirewallBridge(settings, deep_path_enabled=deep_path_enabled)
    if _resolve_engine() == "rust":
        return _RustFirewallBridge(deep_path_enabled=deep_path_enabled)
    return _PythonFirewallBridge(settings, deep_path_enabled=deep_path_enabled)


def get_loop_breaker(**kwargs: Any) -> LoopBreakerBridge:
    """Get the configured loop breaker."""
    if _resolve_engine() == "rust":
        return _RustLoopBridge(**kwargs)
    return _PythonLoopBridge(**kwargs)


def get_egress_policy() -> EgressPolicy | None:
    """Build the egress policy from admina.yaml.

    Returns None when the operator has disabled egress control, so callers
    can skip the pipeline stage entirely rather than running a policy that
    allows everything.

    There is no Rust variant: the stage is a set lookup and a handful of
    string comparisons, so acceleration would not pay for itself.

    A configuration that cannot be read gives an empty allowlist, except a
    file named by ``ADMINA_CONFIG``, whose failure raises
    :class:`~admina.core.config.ConfigFileError`.

    Raises:
        ValueError: ``agent_security.egress.surfaces`` is not a list of
            surface names.
    """
    from admina.core.config import ConfigFileError
    from admina.domains.agent_security.egress import EgressPolicy

    try:
        from admina.core.config import load_config

        cfg = load_config().agent_security.egress
    except ConfigFileError:
        raise
    except Exception as exc:
        logger.warning("Egress config unavailable or malformed, using an empty allowlist: %s", exc)
        return EgressPolicy(allow=[])

    if not cfg.enabled:
        return None
    # read_only_tools is resolved here, from the config already loaded above,
    # and carried on the policy: the pipeline stage must not read config.
    return EgressPolicy(
        allow=list(cfg.allow),
        read_only_tools=frozenset(cfg.read_only_tools),
        surfaces=cfg.surfaces,
    )


# ── PII engine registry and resolver ───────────────────────────────────────

_PII_ENGINE_FACTORIES: dict[str, Callable[[], PIIBridge]] = {}


def _spacy_regex_pii() -> PIIBridge:
    style = pii_mask_style()
    if _resolve_pii_engine() == "rust":
        return _RustPiiBridge(mask_style=style)
    return _PythonPiiBridge(mask_style=style)


_PII_ENGINE_FACTORIES["spacy-regex"] = _spacy_regex_pii


def _presidio_pii() -> PIIBridge:
    from admina.engines.presidio import get_presidio_pii_engine

    return get_presidio_pii_engine()


_PII_ENGINE_FACTORIES["presidio"] = _presidio_pii


def _admina_config() -> AdminaConfig | None:
    """admina.yaml (or the .env fallback), or None when it cannot be read.

    A file named by ``ADMINA_CONFIG`` that cannot be loaded raises
    :class:`~admina.core.config.ConfigFileError`.
    """
    try:
        from admina.core.config import load_config

        return load_config()
    except (ImportError, ValueError, OSError) as exc:
        logger.debug("admina.yaml unavailable, using the PII engine defaults: %s", exc)
        return None


def pii_mask_style() -> str:
    """The mask style of the PII engines: ``ADMINA_PII_MASK_STYLE`` env >
    admina.yaml ``pii_mask_style`` > ``typed``.

    Raises:
        ValueError: the value is not ``typed`` or ``omissis``.
    """
    from admina.domains.data_sovereignty.masking import normalize_mask_style

    value = os.environ.get("ADMINA_PII_MASK_STYLE")
    if not (value or "").strip():
        config = _admina_config()
        value = config.pii_mask_style if config is not None else None
    return normalize_mask_style(value)


def get_pii_engine(name: str | None = None) -> PIIBridge:
    """Get the configured PII engine.

    Resolution order: explicit *name* arg > ``ADMINA_PII_ENGINE`` env >
    admina.yaml ``pii_engine`` > ``spacy-regex``. An engine selected by name
    takes precedence over Rust auto-detection (Rust accelerates only the
    ``spacy-regex`` path).

    A name is looked up among the built-in engines (``spacy-regex``,
    ``presidio``) first, then among the entry points of the
    ``admina.pii_engines`` group (see :mod:`admina.engines.pii_plugins`),
    whose engine runs through a :class:`PIIEngineBridge` and receives its
    ``plugin_config`` block of admina.yaml. Every engine masks in the style
    of :func:`pii_mask_style`. With ``ADMINA_OFFLINE`` the variables of
    :data:`admina.core.offline.OFFLINE_ENVIRONMENT` are set first.

    Raises:
        ValueError: no engine has that name (the message lists the names
            available).
    """
    apply_offline_environment()
    mask_style = pii_mask_style()
    config = None
    if name is None:
        name = os.environ.get("ADMINA_PII_ENGINE") or None
    if name is None:
        config = _admina_config()
        name = config.pii_engine if config is not None else "spacy-regex"
    factory = _PII_ENGINE_FACTORIES.get(name)
    if factory is not None:
        return factory()
    if config is None:
        config = _admina_config()
    plugin_config = (config.plugin_config or {}) if config is not None else {}
    bridge = load_plugin_engine(name, mask_style=mask_style, config=plugin_config.get(name))
    if bridge is None:
        available = sorted({*_PII_ENGINE_FACTORIES, *plugin_engine_names()})
        raise ValueError(f"Unknown pii_engine {name!r}. Available: {available}.")
    return bridge


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
        "pii_active": _resolve_pii_engine(),
    }


__all__ = [
    "ENGINE",
    "FirewallBridge",
    "LoopBreakerBridge",
    "PIIBridge",
    "PIIEngineBridge",
    "engine_status",
    "get_egress_policy",
    "get_firewall",
    "get_loop_breaker",
    "get_pii_engine",
    "get_pii_scanner",
    "pii_mask_style",
]

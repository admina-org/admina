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

"""Admina — Plugin registry with discovery and validation.

The registry scans three locations for plugins:

1. ``plugins/builtin/`` — shipped with Admina.
2. ``~/.admina/plugins/`` — user-installed plugins.
3. ``admina.yaml`` ``plugins:`` list — explicit module paths.

Each discovered module is imported, its classes are validated against the
9 base classes, and matching plugins are registered for runtime lookup.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import sys
from pathlib import Path
from types import ModuleType

from admina.plugins.base import (
    BaseAlertChannel,
    BaseAuthProvider,
    BaseComplianceTemplate,
    BaseDataConnector,
    BaseForensicStore,
    BaseGovernanceGuard,
    BaseModelAdapter,
    BasePIIEngine,
    BaseTransportAdapter,
)

logger = logging.getLogger(__name__)

# Canonical mapping from plugin type key to ABC.
PLUGIN_TYPES: dict[str, type] = {
    "model_adapter": BaseModelAdapter,
    "data_connector": BaseDataConnector,
    "governance_guard": BaseGovernanceGuard,
    "compliance_template": BaseComplianceTemplate,
    "transport_adapter": BaseTransportAdapter,
    "forensic_store": BaseForensicStore,
    "auth_provider": BaseAuthProvider,
    "pii_engine": BasePIIEngine,
    "alert_channel": BaseAlertChannel,
}

# Reverse lookup: ABC → type key.
_BASE_TO_TYPE: dict[type, str] = {v: k for k, v in PLUGIN_TYPES.items()}


def _plugin_type_for_class(cls: type) -> str | None:
    """Return the plugin type key for *cls*, or ``None`` if not a plugin."""
    for base, key in _BASE_TO_TYPE.items():
        if issubclass(cls, base):
            return key
    return None


class PluginRegistry:
    """Central registry for all Admina plugins.

    Usage::

        registry = PluginRegistry()
        registry.discover()                       # scan default locations
        adapter = registry.get("model_adapter", "ollama")
    """

    def __init__(self) -> None:
        # {type_key: {name: class}}
        self._plugins: dict[str, dict[str, type]] = {key: {} for key in PLUGIN_TYPES}

    # ── Public API ──────────────────────────────────────────────

    def register(self, cls: type) -> None:
        """Register a single plugin class.

        Args:
            cls: A concrete subclass of one of the 9 base classes.

        Raises:
            TypeError: If *cls* is not a concrete subclass of a known base.
            ValueError: If the plugin name is already registered for its type.
        """
        if inspect.isabstract(cls):
            raise TypeError(f"Cannot register abstract class {cls.__name__!r}")

        type_key = _plugin_type_for_class(cls)
        if type_key is None:
            raise TypeError(f"{cls.__name__!r} does not extend any known plugin base class")

        name = self._extract_name(cls, type_key)
        bucket = self._plugins[type_key]

        if name in bucket:
            logger.warning(
                "Plugin %s/%s already registered — overwriting with %s",
                type_key,
                name,
                cls.__name__,
            )

        bucket[name] = cls
        logger.debug("Registered plugin %s/%s → %s", type_key, name, cls.__name__)

    def get(self, type_key: str, name: str) -> type | None:
        """Look up a registered plugin class by type and name.

        Args:
            type_key: One of the keys in :data:`PLUGIN_TYPES`
                (e.g. ``"model_adapter"``).
            name: The plugin name (e.g. ``"ollama"``).

        Returns:
            The plugin class, or ``None`` if not found.
        """
        return self._plugins.get(type_key, {}).get(name)

    def list(self, type_key: str) -> dict[str, type]:
        """Return all registered plugins for a given type.

        Args:
            type_key: One of the keys in :data:`PLUGIN_TYPES`.

        Returns:
            A dict mapping name → class.
        """
        return dict(self._plugins.get(type_key, {}))

    def list_all(self) -> dict[str, dict[str, type]]:
        """Return every registered plugin, grouped by type."""
        return {k: dict(v) for k, v in self._plugins.items()}

    def discover(
        self,
        *,
        builtin_path: Path | None = None,
        user_path: Path | None = None,
        extra_modules: list[str] | None = None,
        entry_point_group: str = "admina.plugins",
    ) -> int:
        """Scan plugin sources and register all found plugins.

        Sources scanned, in order:

        1. Builtin (``plugins/builtin/``)
        2. User (``~/.admina/plugins/``)
        3. Explicit module paths from ``admina.yaml`` ``plugins:``
        4. Python entry-points group ``admina.plugins`` — third-party
           packages register plugins via their pyproject.toml without
           being on the filesystem. Example::

               [project.entry-points."admina.plugins"]
               my_adapter = "mypkg.module:MyAdapter"

           or pointing at a module to pick up every concrete plugin
           class it defines::

               [project.entry-points."admina.plugins"]
               my_pack = "mypkg.plugins"

        Args:
            builtin_path: Override for ``plugins/builtin/``.
            user_path: Override for ``~/.admina/plugins/``.
            extra_modules: Dotted module paths from admina.yaml.
            entry_point_group: Entry-points group name to scan.
                Default ``admina.plugins``. Empty string disables it.

        Returns:
            Total number of plugins registered during this call.
        """
        count = 0

        # 1. Built-in plugins — locate the top-level `plugins.builtin`
        #    package via import, so editable installs and installed wheels
        #    both resolve correctly.
        if builtin_path is None:
            try:
                import admina.plugins.builtin as _builtin_pkg

                builtin_path = Path(next(iter(_builtin_pkg.__path__)))
            except (ImportError, StopIteration):
                builtin_path = Path(__file__).parent / "builtin"
        count += self._scan_directory(builtin_path)

        # 2. User plugins
        if user_path is None:
            user_path = Path.home() / ".admina" / "plugins"
        count += self._scan_directory(user_path)

        # 3. Explicit module paths from admina.yaml
        for mod_path in extra_modules or []:
            count += self._load_module_path(mod_path)

        # 4. Entry-points (third-party pip-installed packages)
        if entry_point_group:
            count += self._scan_entry_points(entry_point_group)

        logger.info("Discovery complete — %d plugin(s) registered", count)
        return count

    def _scan_entry_points(self, group: str) -> int:
        """Discover and register plugins exposed via Python entry-points."""
        count = 0
        try:
            from importlib.metadata import entry_points
        except ImportError:  # pragma: no cover (Python < 3.8)
            return 0
        try:
            eps = entry_points(group=group)
        except TypeError:
            # Python 3.9 entry_points() returns a dict
            eps = entry_points().get(group, [])  # type: ignore[assignment]
        for ep in eps:
            try:
                obj = ep.load()
            except Exception:  # noqa: BLE001 — third-party code, isolate
                logger.warning(
                    "Failed to load entry-point plugin %s from %s",
                    ep.name,
                    ep.value,
                    exc_info=True,
                )
                continue
            if inspect.isclass(obj):
                try:
                    self.register(obj)
                    count += 1
                except (TypeError, ValueError):
                    logger.warning(
                        "Entry-point %s exposes %s but it is not a valid plugin",
                        ep.name,
                        obj.__name__,
                    )
            elif inspect.ismodule(obj):
                count += self._register_from_module(obj)
            else:
                logger.warning(
                    "Entry-point %s loaded %r — expected a class or module",
                    ep.name,
                    obj,
                )
        return count

    # ── Internal helpers ────────────────────────────────────────

    def _scan_directory(self, directory: Path) -> int:
        """Import all ``.py`` modules under *directory* and register plugins."""
        if not directory.is_dir():
            logger.debug("Plugin directory does not exist: %s", directory)
            return 0

        count = 0
        for py_file in sorted(directory.rglob("*.py")):
            if py_file.name == "__init__.py":
                continue
            count += self._load_file(py_file)

        return count

    def _load_file(self, py_file: Path) -> int:
        """Import a single ``.py`` file and register all plugin classes."""
        mod_name = f"_admina_plugin_{py_file.stem}_{id(py_file)}"
        try:
            spec = importlib.util.spec_from_file_location(mod_name, str(py_file))
            if spec is None or spec.loader is None:
                return 0
            mod = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = mod
            spec.loader.exec_module(mod)
        except ModuleNotFoundError as exc:
            logger.warning(
                "Skipping plugin %s — optional dependency %r not installed",
                py_file.stem,
                exc.name or "?",
            )
            return 0
        except (ImportError, AttributeError, RuntimeError):
            logger.warning("Failed to import plugin file %s", py_file, exc_info=True)
            return 0

        return self._register_from_module(mod)

    def _load_module_path(self, mod_path: str) -> int:
        """Import a module by dotted path and register all plugin classes."""
        try:
            mod = importlib.import_module(mod_path)
        except ModuleNotFoundError as exc:
            logger.warning(
                "Skipping plugin module %r — optional dependency %r not installed",
                mod_path,
                exc.name or "?",
            )
            return 0
        except ImportError:
            logger.warning("Failed to import plugin module %r", mod_path, exc_info=True)
            return 0

        return self._register_from_module(mod)

    def _register_from_module(self, mod: ModuleType) -> int:
        """Find and register all concrete plugin classes in *mod*."""
        count = 0
        for _attr_name, obj in inspect.getmembers(mod, inspect.isclass):
            # Skip the ABCs themselves and classes not defined in this module
            if obj.__module__ != mod.__name__:
                continue
            if inspect.isabstract(obj):
                continue
            if _plugin_type_for_class(obj) is not None:
                self.register(obj)
                count += 1
        return count

    @staticmethod
    def _extract_name(cls: type, type_key: str) -> str:
        """Extract the canonical name from a plugin class.

        Tries the property/attribute that matches the base class contract
        (``name``, ``protocol_name``, ``store_name``, etc.).  Falls back
        to the lower-cased class name.
        """
        # Map type_key → property name on the ABC
        name_attrs = {
            "model_adapter": "name",
            "data_connector": "name",
            "governance_guard": "name",
            "compliance_template": "framework_name",
            "transport_adapter": "protocol_name",
            "forensic_store": "store_name",
            "auth_provider": "provider_name",
            "pii_engine": "supported_languages",
            "alert_channel": "channel_name",
        }

        attr = name_attrs.get(type_key, "name")

        # For pii_engine, the identifier is not a name property — use class name
        if type_key == "pii_engine":
            return cls.__name__.lower()

        # Try to get from a class-level attribute (not an instance property)
        # Instantiation-free: check if the class defines the attr as a plain value
        for klass in cls.__mro__:
            if attr in klass.__dict__:
                val = klass.__dict__[attr]
                # If it's a plain value (str), use it
                if isinstance(val, str):
                    return val
                # If it's a property, we can't call it without an instance
                break

        # Fallback: lower-cased class name
        return cls.__name__.lower()

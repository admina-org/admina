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

"""Admina — PII engines of other packages.

A package makes a PII engine selectable by name (``ADMINA_PII_ENGINE``,
``pii_engine`` in admina.yaml) with an entry point of the group
``admina.pii_engines``::

    [project.entry-points."admina.pii_engines"]
    example-pii = "example_pkg.engine:ExamplePIIEngine"

The entry point names a :class:`~admina.plugins.base.BasePIIEngine`
subclass, or a callable that returns an instance of one. A class (or
callable) with a ``config`` parameter receives the ``plugin_config`` block
of admina.yaml under the engine's name. :class:`PIIEngineBridge` wraps the
engine into the synchronous ``PIIBridge`` that the governance pipeline, the
SDK and the gateway use.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
import weakref
from collections.abc import Coroutine
from importlib import metadata
from typing import Any, TypeVar

from admina.domains.data_sovereignty.masking import (
    mask_omissis,
    normalize_mask_style,
    outside_placeholders,
    placeholder_spans,
)
from admina.plugins.base import BasePIIEngine

logger = logging.getLogger("admina.engines.pii_plugins")

__all__ = ["PII_ENGINES_GROUP", "PIIEngineBridge", "load_plugin_engine", "plugin_engine_names"]

PII_ENGINES_GROUP = "admina.pii_engines"
"""Entry-point group of the PII engines of other packages."""

T = TypeVar("T")


def _entry_points() -> list[metadata.EntryPoint]:
    return list(metadata.entry_points(group=PII_ENGINES_GROUP))


def plugin_engine_names() -> list[str]:
    """The names of the engines registered in :data:`PII_ENGINES_GROUP`."""
    return sorted({ep.name for ep in _entry_points()})


def load_plugin_engine(
    name: str, *, mask_style: str = "typed", config: Any = None
) -> PIIEngineBridge | None:
    """The engine registered as *name* in :data:`PII_ENGINES_GROUP`, wrapped
    in a :class:`PIIEngineBridge` with *mask_style*; None when no entry
    point has that name.

    *config* goes to an engine whose class (or factory) has a ``config``
    parameter.

    Raises:
        ImportError: the entry point cannot be loaded.
        TypeError: it does not give a ``BasePIIEngine``.
        ValueError: entry points of that name name different objects.
    """
    found = [ep for ep in _entry_points() if ep.name == name]
    if not found:
        return None
    values = sorted({ep.value for ep in found})
    if len(values) > 1:
        raise ValueError(f"PII engine {name!r} is registered more than once: {values}")
    entry_point = found[0]
    try:
        target = entry_point.load()
    except ImportError as exc:
        raise ImportError(
            f"PII engine {name!r} ({entry_point.value}) cannot be loaded: {exc}"
        ) from exc
    engine = _instantiate(name, target, config)
    logger.info("[OK] PII engine %r loaded from %s", name, entry_point.value)
    return PIIEngineBridge(engine, mask_style=mask_style, name=name)


def _instantiate(name: str, target: Any, config: Any) -> BasePIIEngine:
    if inspect.isclass(target) and not issubclass(target, BasePIIEngine):
        raise TypeError(f"PII engine {name!r}: {target.__name__} is not a BasePIIEngine")
    if not callable(target):
        raise TypeError(f"PII engine {name!r}: {target!r} is not a BasePIIEngine")
    try:
        parameters = inspect.signature(target).parameters
    except (TypeError, ValueError):
        parameters = {}
    engine = target(config=config) if "config" in parameters else target()
    if not isinstance(engine, BasePIIEngine):
        raise TypeError(f"PII engine {name!r}: {target!r} did not return a BasePIIEngine")
    return engine


def _serve(loop: asyncio.AbstractEventLoop) -> None:
    try:
        loop.run_forever()
    finally:
        loop.close()


class _EngineLoop:
    """An event loop in a thread of its own, started on first use, where the
    coroutines of one engine run: the engine can be called from any thread,
    with or without an event loop running there, and its loop-bound
    resources stay on one loop. The loop stops when this object is
    garbage-collected."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    def run(self, coroutine: Coroutine[Any, Any, T]) -> T:
        loop = self._started()
        if threading.current_thread() is self._thread:
            coroutine.close()
            raise RuntimeError(f"PII engine {self._name!r} called from its own event loop")
        return asyncio.run_coroutine_threadsafe(coroutine, loop).result()

    def _started(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop is None:
                loop = asyncio.new_event_loop()
                thread = threading.Thread(
                    target=_serve, args=(loop,), name=f"admina-pii-{self._name}", daemon=True
                )
                thread.start()
                self._loop, self._thread = loop, thread
                weakref.finalize(self, loop.call_soon_threadsafe, loop.stop)
            return self._loop


class PIIEngineBridge:
    """The synchronous ``PIIBridge`` of an asynchronous
    :class:`~admina.plugins.base.BasePIIEngine`.

    ``redact(text)`` runs the engine's ``detect`` on the engine's own event
    loop and returns ``{"redacted_text", "entities", "categories",
    "count"}``. In the ``typed`` mask style the text is the engine's own
    ``redact``; in the ``omissis`` style Admina masks each span with
    ``[OMISSIS]`` and, for the engine's ``sentence_categories``, the
    sentences (the engine's ``sentences``) that the span overlaps. Each
    entity has ``type``, ``start``, ``end``, ``original_length`` and
    ``method`` (the engine's name), never the text it covers. A placeholder
    already in the text (``[EMAIL]``, ``[OMISSIS]``, …) is never masked
    again: a detected span is reduced to its parts outside the
    placeholders. A span outside the text, or without a string ``type``,
    raises ``ValueError``.

    Args:
        engine: The engine.
        mask_style: ``typed`` (default) or ``omissis``.
        name: Its name (default: the engine's ``name`` attribute, else its
            class name).
    """

    def __init__(
        self, engine: BasePIIEngine, *, mask_style: str = "typed", name: str | None = None
    ) -> None:
        self.engine = engine
        self.mask_style = normalize_mask_style(mask_style)
        self.name = name or str(getattr(engine, "name", "") or type(engine).__name__)
        self.total_redacted = 0
        self.redactions_by_type: dict[str, int] = {}
        self._stats_lock = threading.Lock()
        self._loop = _EngineLoop(self.name)

    @property
    def special_categories(self) -> frozenset[str]:
        """The special categories of personal data the engine declares."""
        return frozenset(self.engine.special_categories)

    @property
    def masks_sentences(self) -> bool:
        """True when whole sentences are masked (``omissis`` and an engine
        with ``sentence_categories``): a stream is then released at the
        start of a sentence (:meth:`sentence_start`)."""
        return self.mask_style == "omissis" and bool(self.engine.sentence_categories)

    def sentence_start(self, text: str, position: int) -> int:
        """The start of the sentence of *text* that holds *position*: the
        text before it is made of whole sentences; 0 when there is none."""
        starts = [start for start, _end in self.engine.sentences(text) if start <= position]
        return max(starts, default=0)

    def redact(self, text: str) -> dict[str, Any]:
        if not text:
            return {"redacted_text": text, "entities": [], "categories": [], "count": 0}
        matches = self._matches(text, self._loop.run(self.engine.detect(text)))
        redacted = self._masked(text, matches)
        entities = [
            {
                "type": m["type"],
                "start": m["start"],
                "end": m["end"],
                "original_length": m["end"] - m["start"],
                "method": self.name,
            }
            for m in matches
        ]
        self._count(entities)
        return {
            "redacted_text": redacted,
            "entities": entities,
            "categories": sorted({e["type"] for e in entities}),
            "count": len(entities),
        }

    def _masked(self, text: str, matches: list[dict]) -> str:
        if not matches:
            return text
        if self.mask_style == "omissis":
            sentence_categories = frozenset(self.engine.sentence_categories)
            needs_sentences = any(m["type"] in sentence_categories for m in matches)
            return mask_omissis(
                text,
                [(m["start"], m["end"], m["type"]) for m in matches],
                sentence_categories=sentence_categories,
                sentences=self.engine.sentences(text) if needs_sentences else None,
            )
        redacted = self._loop.run(self.engine.redact(text, matches))
        if not isinstance(redacted, str):
            raise TypeError(f"PII engine {self.name!r} returned {type(redacted).__name__}")
        return redacted

    def get_stats(self) -> dict[str, Any]:
        with self._stats_lock:
            by_type = dict(self.redactions_by_type)
            total = self.total_redacted
        return {
            "total_redacted": total,
            "redactions_by_type": by_type,
            "engine": self.name,
            "languages": list(self.engine.supported_languages),
        }

    def _matches(self, text: str, detected: Any) -> list[dict]:
        """The detected spans, checked and reduced to their parts outside
        the placeholders already in *text*."""
        if not isinstance(detected, list):
            raise ValueError(f"PII engine {self.name!r} did not return a list of matches")
        placeholders = placeholder_spans(text)
        matches: list[dict] = []
        for match in detected:
            start, end, kind = self._checked(text, match)
            for a, b in outside_placeholders(start, end, placeholders, text):
                matches.append({**match, "type": kind, "start": a, "end": b, "text": text[a:b]})
        return matches

    def _checked(self, text: str, match: Any) -> tuple[int, int, str]:
        fields = match if isinstance(match, dict) else {}
        start, end, kind = fields.get("start"), fields.get("end"), fields.get("type")
        if (
            isinstance(start, int)
            and isinstance(end, int)
            and isinstance(kind, str)
            and 0 <= start < end <= len(text)
        ):
            return start, end, kind
        raise ValueError(f"PII engine {self.name!r} returned a span outside the text")

    def _count(self, entities: list[dict]) -> None:
        if not entities:
            return
        with self._stats_lock:
            self.total_redacted += len(entities)
            for entity in entities:
                kind = entity["type"]
                self.redactions_by_type[kind] = self.redactions_by_type.get(kind, 0) + 1

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

"""Third-party PII engines for the tests, installed as the ``example-pii``
distribution of this directory (see its ``entry_points.txt``).

:class:`ExamplePIIEngine` detects e-mail addresses, Italian fiscal codes,
IBANs, phone numbers and health terms; ``HEALTH`` is a special category
that it masks as a whole sentence.
"""

from __future__ import annotations

import asyncio
import re

from admina.plugins.base import BasePIIEngine

_PATTERNS = {
    "EMAIL": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    "CODICE_FISCALE": re.compile(r"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b"),
    "IBAN": re.compile(r"\bIT\d{2}(?: ?[A-Z0-9]){23}\b"),
    "PHONE": re.compile(r"\+39 ?\d{2,3} ?\d{3} ?\d{3,4}"),
    "HEALTH": re.compile(r"\b(?:diagnosi|ricovero|terapia|diabete)\b", re.IGNORECASE),
}


class ExamplePIIEngine(BasePIIEngine):
    name = "example-pii"
    sentence_categories = frozenset({"HEALTH"})
    special_categories = frozenset({"HEALTH"})

    @property
    def supported_languages(self) -> list[str]:
        return ["it"]

    async def detect(self, text: str, categories: list[str] | None = None) -> list[dict]:
        await asyncio.sleep(0)  # a real await: the engine runs on an event loop
        found = []
        for kind, pattern in _PATTERNS.items():
            if categories and kind not in categories:
                continue
            for m in pattern.finditer(text):
                found.append(
                    {
                        "type": kind,
                        "start": m.start(),
                        "end": m.end(),
                        "text": m.group(),
                        "confidence": 0.9,
                    }
                )
        return sorted(found, key=lambda m: m["start"])

    async def redact(self, text: str, matches: list[dict]) -> str:
        for m in sorted(matches, key=lambda m: m["start"], reverse=True):
            text = text[: m["start"]] + f"[{m['type']}]" + text[m["end"] :]
        return text


class EveryWordPIIEngine(ExamplePIIEngine):
    """Flags every word as a PERSON, as an over-eager NER model might."""

    name = "every-word"
    sentence_categories = frozenset()
    special_categories = frozenset()

    async def detect(self, text: str, categories: list[str] | None = None) -> list[dict]:
        return [
            {"type": "PERSON", "start": m.start(), "end": m.end(), "text": m.group()}
            for m in re.finditer(r"\w+", text)
        ]


class ConfiguredPIIEngine(ExamplePIIEngine):
    """Keeps the ``plugin_config`` block it receives."""

    name = "configured-pii"

    def __init__(self, config: dict | None = None) -> None:
        self.config = config


class BadSpanPIIEngine(ExamplePIIEngine):
    """Reports a span past the end of the text."""

    name = "bad-span-pii"

    async def detect(self, text: str, categories: list[str] | None = None) -> list[dict]:
        return [{"type": "EMAIL", "start": 0, "end": len(text) + 5, "text": text}]


class NotAnEngine:
    """Not a BasePIIEngine."""


def make_engine() -> ExamplePIIEngine:
    """A factory entry point."""
    return ExamplePIIEngine()

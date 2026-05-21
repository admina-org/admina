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

"""Admina — spaCy + regex PII engine plugin.

Wraps the existing PII redactor as a :class:`BasePIIEngine` plugin.
Uses regex patterns for structured PII (email, phone, CC, SSN, IBAN, IP)
and spaCy NER for named entities (PERSON, ORG, GPE).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from admina.plugins.base import BasePIIEngine

logger = logging.getLogger("admina.plugins.pii.spacy_regex")

# Regex patterns for structured PII
_PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "PHONE": re.compile(r"(?<!\d)(\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "IBAN": re.compile(
        r"\b[A-Z]{2}\d{2}\s?[\dA-Z]{4}\s?[\dA-Z]{4}\s?[\dA-Z]{4}"
        r"(?:\s?[\dA-Z]{4}){0,4}\b"
    ),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

# spaCy entity labels we care about
_NER_LABELS = {"PERSON", "ORG", "GPE", "LOC"}


class SpaCyRegexPIIEngine(BasePIIEngine):
    """PII engine combining regex patterns and spaCy NER.

    The spaCy model is loaded lazily on first use.  If the model is
    not installed, the engine falls back to regex-only mode.
    """

    def __init__(self, ner_model: str = "en_core_web_sm") -> None:
        self._ner_model = ner_model
        self._nlp: Any = None
        self._nlp_loaded = False

    def _get_nlp(self) -> Any:
        """Lazily load the spaCy model."""
        if not self._nlp_loaded:
            self._nlp_loaded = True
            try:
                import spacy  # type: ignore[import-untyped]

                self._nlp = spacy.load(self._ner_model)
            except (ImportError, OSError):
                logger.warning(
                    "spaCy model %r not available — using regex-only mode",
                    self._ner_model,
                )
                self._nlp = None
        return self._nlp

    # ── BasePIIEngine interface ─────────────────────────────────

    async def detect(
        self,
        text: str,
        categories: list[str] | None = None,
    ) -> list[dict]:
        """Detect PII entities in *text*.

        Args:
            text: Input text.
            categories: Optional allowlist of PII types.

        Returns:
            List of ``{"type", "start", "end", "text", "confidence"}`` dicts.
        """
        if not text:
            return []

        allowed = set(categories) if categories else None
        matches: list[dict] = []

        # Step 1 — regex pass
        for pii_type, pattern in _PATTERNS.items():
            if allowed and pii_type not in allowed:
                continue
            for m in pattern.finditer(text):
                matches.append(
                    {
                        "type": pii_type,
                        "start": m.start(),
                        "end": m.end(),
                        "text": m.group(),
                        "confidence": 0.95,
                    }
                )

        # Step 2 — spaCy NER pass
        nlp = self._get_nlp()
        if nlp is not None:
            doc = nlp(text)
            for ent in doc.ents:
                if ent.label_ not in _NER_LABELS:
                    continue
                if allowed and ent.label_ not in allowed:
                    continue
                # Skip if already covered by a regex match
                overlap = any(m["start"] <= ent.start_char < m["end"] for m in matches)
                if overlap:
                    continue
                matches.append(
                    {
                        "type": ent.label_,
                        "start": ent.start_char,
                        "end": ent.end_char,
                        "text": ent.text,
                        "confidence": 0.85,
                    }
                )

        # Sort by position
        matches.sort(key=lambda m: m["start"])
        return matches

    async def redact(self, text: str, matches: list[dict]) -> str:
        """Replace detected PII with type-based placeholders.

        Args:
            text: Original text.
            matches: Output from :meth:`detect`.

        Returns:
            Redacted text.
        """
        # Process in reverse order to preserve positions
        for m in sorted(matches, key=lambda x: x["start"], reverse=True):
            placeholder = f"[{m['type']}]"
            text = text[: m["start"]] + placeholder + text[m["end"] :]
        return text

    @property
    def supported_languages(self) -> list[str]:
        """Supported languages."""
        return ["en"]

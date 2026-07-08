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

"""Admina — Microsoft Presidio PII engine (analyzer-only).

Presidio performs *detection*; Admina performs the *masking*, so the output
format is identical to the spaCy+regex engine (the per-category mask from
``PII_CATEGORIES``, e.g. ``[EMAIL]`` / ``[PERSON]``). Registered on the
synchronous ``PIIBridge`` factory path (admina/engines/__init__.py), NOT the
async ``BasePIIEngine`` plugin ABC.

Languages: EN + IT. Each configured language whose spaCy model is installed is
analyzed and the results are unioned, so an entity a recognizer only registers
for one language (e.g. IT_FISCAL_CODE under "it") is still caught. Presidio and
its models are an optional extra:
    pip install 'admina-framework[presidio]'
    python -m spacy download en_core_web_sm it_core_news_sm
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from admina.domains.data_sovereignty.pii import PII_CATEGORIES

logger = logging.getLogger("admina.engines.presidio")

# Presidio entity_type -> Admina PII_CATEGORIES key. Unmapped Presidio types
# (DATE_TIME, URL, NRP, ...) are intentionally ignored so the category set and
# false-positive profile stay aligned with the spaCy+regex engine.
_PRESIDIO_TO_ADMINA: dict[str, str] = {
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "CREDIT_CARD": "CREDIT_CARD",
    "IBAN_CODE": "IBAN",
    "IP_ADDRESS": "IP_ADDRESS",
    "US_SSN": "SSN",
    "PERSON": "PERSON",
    "LOCATION": "GPE",
    "ORGANIZATION": "ORG",
    "IT_FISCAL_CODE": "IT_CODICE_FISCALE",
    "ES_NIF": "ES_DNI_NIE",
    "ES_NIE": "ES_DNI_NIE",
}

# Languages Admina configures for Presidio, each mapped to its spaCy model.
_LANG_MODELS: dict[str, str] = {
    "en": "en_core_web_sm",
    "it": "it_core_news_sm",
}


def _build_analyzer(languages: tuple[str, ...]):
    """Build a Presidio AnalyzerEngine over the given (installed) languages."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": lang, "model_name": _LANG_MODELS[lang]} for lang in languages],
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=configuration).create_engine()
    return AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=list(languages))


class PresidioPIIEngine:
    """Synchronous ``PIIBridge`` backed by Microsoft Presidio (analyzer-only)."""

    def __init__(self) -> None:
        try:
            import presidio_analyzer  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "The Presidio PII engine requires the [presidio] extra. Install it with "
                "`pip install 'admina-framework[presidio]'` and download the models "
                "`python -m spacy download en_core_web_sm it_core_news_sm`."
            ) from exc

        import spacy

        languages = tuple(
            lang for lang, model in _LANG_MODELS.items() if spacy.util.is_package(model)
        )
        if not languages:
            raise ImportError(
                "Presidio is installed but no supported spaCy model is present. Run "
                "`python -m spacy download en_core_web_sm it_core_news_sm`."
            )
        self.languages: list[str] = list(languages)
        self._analyzer = _build_analyzer(languages)
        self.total_redacted: int = 0
        self.redactions_by_type: dict[str, int] = {}
        logger.info("[OK] Presidio PII engine ready (languages: %s)", self.languages)

    def redact(self, text: str) -> dict[str, Any]:
        if not text:
            return {"redacted_text": text, "entities": [], "categories": [], "count": 0}

        # Union of per-language analyses: a recognizer registered for only one
        # language is missed by the other pass, so both are run and merged.
        raw = []
        for lang in self.languages:
            raw.extend(self._analyzer.analyze(text=text, language=lang))

        spans: list[tuple[int, int, str, str]] = []
        for r in raw:
            category = _PRESIDIO_TO_ADMINA.get(r.entity_type)
            if category is None:
                continue
            cfg = PII_CATEGORIES.get(category, {})
            if not cfg.get("enabled", False):
                continue
            spans.append((r.start, r.end, category, cfg.get("mask", f"[{category}]")))

        # Resolve overlaps deterministically: earliest start first, longest on
        # ties; greedily drop any span overlapping an already-accepted one. This
        # also dedupes the same span produced by two language passes.
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        accepted: list[tuple[int, int, str, str]] = []
        last_end = -1
        for start, end, category, mask in spans:
            if start >= last_end:
                accepted.append((start, end, category, mask))
                last_end = end

        entities = [
            {
                "type": category,
                "start": start,
                "end": end,
                "original_length": end - start,
                "method": "presidio",
            }
            for (start, end, category, mask) in accepted
        ]
        redacted = text
        for start, end, _category, mask in sorted(accepted, key=lambda s: s[0], reverse=True):
            redacted = redacted[:start] + mask + redacted[end:]

        count = len(entities)
        if count:
            self.total_redacted += count
            for ent in entities:
                self.redactions_by_type[ent["type"]] = (
                    self.redactions_by_type.get(ent["type"], 0) + 1
                )
        categories = sorted({ent["type"] for ent in entities})
        return {
            "redacted_text": redacted,
            "entities": entities,
            "categories": categories,
            "count": count,
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_redacted": self.total_redacted,
            "redactions_by_type": self.redactions_by_type,
            "spacy_available": True,
            "engine": "presidio",
            "languages": list(self.languages),
        }


@lru_cache(maxsize=1)
def get_presidio_pii_engine() -> PresidioPIIEngine:
    """Return a process-wide cached Presidio engine (analyzer construction is costly)."""
    return PresidioPIIEngine()

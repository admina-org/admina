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
``PII_CATEGORIES``, e.g. ``[EMAIL]`` / ``[PERSON]``, or ``[OMISSIS]`` in the
``omissis`` mask style). A detected span is masked only outside the
placeholders already in the text. Registered on the
synchronous ``PIIBridge`` factory path (admina/engines/__init__.py), NOT the
async ``BasePIIEngine`` plugin ABC.

Languages: each language has a spaCy pipeline, and the analyses of all the
languages are unioned, so an entity a recognizer only registers for one
language (e.g. IT_FISCAL_CODE under "it") is still caught.
``ADMINA_PRESIDIO_NLP_MODELS`` (``it:blank,en:en_core_web_sm``) or
``presidio.nlp_models`` in admina.yaml maps each language to an installed
spaCy model or to ``blank``: ``spacy.blank(language)``, a tokenizer with no
model and no NER, so the pattern recognizers (e-mail, IBAN, fiscal codes,
phone numbers, …) still run. Without that setting, each of ``en_core_web_sm``
(en) and ``it_core_news_sm`` (it) that is installed is used. A configured
model that is not installed stops the engine: models are never downloaded.

E-mail domains are checked against the public suffix list bundled with
tldextract, with no cache and no download, so the engine makes no network
access. Presidio is an optional extra:
    pip install 'admina-framework[presidio]'
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from admina.domains.data_sovereignty.masking import (
    OMISSIS,
    normalize_mask_style,
    outside_placeholders,
    placeholder_spans,
    replace_spans,
)
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

# The Presidio entity types requested from the analyzer.
_ENTITIES: list[str] = list(_PRESIDIO_TO_ADMINA)

# The spaCy model of each language used when no pipeline is configured, if
# it is installed.
_DEFAULT_MODELS: dict[str, str] = {
    "en": "en_core_web_sm",
    "it": "it_core_news_sm",
}

BLANK = "blank"
"""The pipeline name of ``spacy.blank(language)``: a tokenizer, no model."""

NLP_MODELS_ENV = "ADMINA_PRESIDIO_NLP_MODELS"


def parse_nlp_models(value: str) -> dict[str, str]:
    """The pipelines of ``ADMINA_PRESIDIO_NLP_MODELS``: comma-separated
    ``language:model`` pairs, in order.

    Raises:
        ValueError: a pair without a language or a model, or a language
            given twice.
    """
    models: dict[str, str] = {}
    for item in value.split(","):
        if not item.strip():
            continue
        lang, colon, model = (part.strip() for part in item.partition(":"))
        if not colon or not lang or not model or lang in models:
            raise ValueError(
                f"{NLP_MODELS_ENV} must be comma-separated language:model pairs, "
                "each language once (model: an installed spaCy model, or blank)"
            )
        models[lang] = model
    return models


def presidio_nlp_models() -> dict[str, str]:
    """The configured pipelines: ``ADMINA_PRESIDIO_NLP_MODELS`` env >
    admina.yaml ``presidio.nlp_models`` > ``{}`` (the default models).

    Raises:
        ValueError: the setting is malformed.
    """
    raw = os.environ.get(NLP_MODELS_ENV, "")
    if raw.strip():
        return parse_nlp_models(raw)
    from admina.engines import _admina_config

    config = _admina_config()
    if config is None:
        return {}
    if config.presidio.errors:
        raise ValueError("; ".join(config.presidio.errors))
    return dict(config.presidio.nlp_models)


def _pipelines(nlp_models: Mapping[str, str] | None) -> dict[str, str]:
    """The pipeline of each language: *nlp_models* checked, or the default
    models that are installed.

    Raises:
        ImportError: a configured model is not installed, or no default
            model is.
        ValueError: spaCy has no such language.
    """
    import spacy

    if not nlp_models:
        installed = {
            lang: model for lang, model in _DEFAULT_MODELS.items() if spacy.util.is_package(model)
        }
        if not installed:
            raise ImportError(
                "Presidio is installed but no default spaCy model is: install "
                f"{' or '.join(_DEFAULT_MODELS.values())}, or set {NLP_MODELS_ENV} "
                "(presidio.nlp_models) to a pipeline such as it:blank."
            )
        return installed
    for lang, model in nlp_models.items():
        try:
            spacy.util.get_lang_class(lang)
        except ImportError as exc:
            raise ValueError(f"Presidio NLP models: spaCy has no language {lang!r}") from exc
        if model != BLANK and not (spacy.util.is_package(model) or Path(model).is_dir()):
            raise ImportError(
                f"Presidio NLP models: the spaCy model {model!r} ({lang}) is not installed; "
                "models are never downloaded: install its package, or use blank."
            )
    return dict(nlp_models)


def _suffix_extractor() -> Any:
    """A tldextract extractor that reads only the public suffix list
    bundled with tldextract: no download, no cache files."""
    import tldextract

    return tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), fallback_to_snapshot=True)


def _build_analyzer(pipelines: dict[str, str]):
    """A Presidio AnalyzerEngine over *pipelines* (language → model or
    ``blank``), whose e-mail recognizers check domains offline."""
    import spacy
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import SpacyNlpEngine
    from presidio_analyzer.predefined_recognizers import EmailRecognizer

    class LocalSpacyNlpEngine(SpacyNlpEngine):
        """Loads installed models and blank pipelines; never downloads."""

        def load(self) -> None:
            self.nlp = {
                m["lang_code"]: (
                    spacy.blank(m["lang_code"])
                    if m["model_name"] == BLANK
                    else spacy.load(m["model_name"])
                )
                for m in self.models
            }

    extractor = _suffix_extractor()
    extractor("example.org")  # read the bundled list now, not on the first request

    class SnapshotEmailRecognizer(EmailRecognizer):
        def validate_result(self, pattern_text: str) -> bool:
            return extractor(pattern_text).fqdn != ""

    languages = list(pipelines)
    nlp_engine = LocalSpacyNlpEngine(
        models=[{"lang_code": lang, "model_name": model} for lang, model in pipelines.items()]
    )
    nlp_engine.load()
    registry = RecognizerRegistry(supported_languages=languages)
    registry.load_predefined_recognizers(languages=languages, nlp_engine=nlp_engine)
    registry.recognizers = [
        SnapshotEmailRecognizer(supported_language=r.supported_language)
        if type(r) is EmailRecognizer
        else r
        for r in registry.recognizers
    ]
    return AnalyzerEngine(registry=registry, nlp_engine=nlp_engine, supported_languages=languages)


class PresidioPIIEngine:
    """Synchronous ``PIIBridge`` backed by Microsoft Presidio (analyzer-only).

    Args:
        mask_style: ``typed`` (default) or ``omissis``.
        nlp_models: The pipeline of each language (model name or ``blank``);
            None or empty: the default models that are installed.
    """

    def __init__(
        self, *, mask_style: str = "typed", nlp_models: Mapping[str, str] | None = None
    ) -> None:
        self.mask_style = normalize_mask_style(mask_style)
        try:
            import presidio_analyzer  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "The Presidio PII engine requires the [presidio] extra. Install it with "
                "`pip install 'admina-framework[presidio]'`."
            ) from exc

        pipelines = _pipelines(nlp_models)
        self.languages: list[str] = list(pipelines)
        self.pipelines: dict[str, str] = pipelines
        self._analyzer = _build_analyzer(pipelines)
        self.total_redacted: int = 0
        self.redactions_by_type: dict[str, int] = {}
        logger.info("[OK] Presidio PII engine ready (pipelines: %s)", self.pipelines)

    def redact(self, text: str) -> dict[str, Any]:
        if not text:
            return {"redacted_text": text, "entities": [], "categories": [], "count": 0}

        # Union of per-language analyses: a recognizer registered for only one
        # language is missed by the other pass, so both are run and merged.
        # Only the mapped entity types are requested: the other recognizers
        # (URL among them, slow on text with many dots) would be discarded.
        raw = []
        for lang in self.languages:
            raw.extend(self._analyzer.analyze(text=text, language=lang, entities=_ENTITIES))

        placeholders = placeholder_spans(text)
        spans: list[tuple[int, int, str, str]] = []
        for r in raw:
            category = _PRESIDIO_TO_ADMINA.get(r.entity_type)
            if category is None:
                continue
            cfg = PII_CATEGORIES.get(category, {})
            if not cfg.get("enabled", False):
                continue
            mask = OMISSIS if self.mask_style == "omissis" else cfg.get("mask", f"[{category}]")
            for start, end in outside_placeholders(r.start, r.end, placeholders, text):
                spans.append((start, end, category, mask))

        # Resolve overlaps deterministically: earliest start first, longest on
        # ties; a span that overlaps an accepted one extends it to their union,
        # which keeps the category and mask of the accepted span. This also
        # dedupes the same span produced by two language passes.
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        accepted: list[tuple[int, int, str, str]] = []
        for start, end, category, mask in spans:
            if accepted and start < accepted[-1][1]:
                first_start, first_end, first_category, first_mask = accepted[-1]
                if end > first_end:
                    accepted[-1] = (first_start, end, first_category, first_mask)
                continue
            accepted.append((start, end, category, mask))

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
        # The accepted spans are in order and do not overlap: one pass.
        redacted = replace_spans(text, ((start, end, mask) for start, end, _c, mask in accepted))

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


def get_presidio_pii_engine(
    mask_style: str | None = None, nlp_models: Mapping[str, str] | None = None
) -> PresidioPIIEngine:
    """Return a process-wide cached Presidio engine (analyzer construction is
    costly), one per mask style and pipelines (defaults:
    :func:`admina.engines.pii_mask_style` and :func:`presidio_nlp_models`)."""
    if mask_style is None:
        from admina.engines import pii_mask_style

        mask_style = pii_mask_style()
    if nlp_models is None:
        nlp_models = presidio_nlp_models()
    return _cached_engine(normalize_mask_style(mask_style), tuple(nlp_models.items()))


@lru_cache(maxsize=4)
def _cached_engine(mask_style: str, nlp_models: tuple[tuple[str, str], ...]) -> PresidioPIIEngine:
    return PresidioPIIEngine(mask_style=mask_style, nlp_models=dict(nlp_models))

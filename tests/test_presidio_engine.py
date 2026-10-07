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

"""admina.engines.presidio — Presidio PII engine (analyzer-only, PIIBridge)."""

from __future__ import annotations

import builtins

import pytest


def test_presidio_missing_dependency_error_is_actionable(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "presidio_analyzer" or name.startswith("presidio_analyzer."):
            raise ImportError("No module named 'presidio_analyzer'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    from admina.engines.presidio import PresidioPIIEngine

    with pytest.raises(ImportError, match=r"admina\[presidio\]"):
        PresidioPIIEngine()


def _engine_or_skip():
    pytest.importorskip("presidio_analyzer")
    from admina.engines.presidio import PresidioPIIEngine

    try:
        return PresidioPIIEngine()
    except ImportError:
        pytest.skip("presidio installed but spaCy models not downloaded")


def test_presidio_redacts_email_and_person_with_admina_masks():
    out = _engine_or_skip().redact("Contact John Smith at john.smith@example.com")
    assert "[EMAIL]" in out["redacted_text"]
    assert "[PERSON]" in out["redacted_text"]
    assert "john.smith@example.com" not in out["redacted_text"]
    assert "EMAIL" in out["categories"] and "PERSON" in out["categories"]
    assert out["count"] == len(out["entities"]) >= 2
    assert all(e["method"] == "presidio" for e in out["entities"])


def test_presidio_mask_format_parity_with_spacy_regex():
    # Same mask token the default spaCy+regex engine emits
    # (cf. tests/test_engines.py::test_pii_engine_resolver_default_and_unknown).
    out = _engine_or_skip().redact("mail me at someone@example.com")
    assert "[EMAIL]" in out["redacted_text"]
    assert "someone@example.com" not in out["redacted_text"]


def test_presidio_empty_text_returns_full_shape():
    out = _engine_or_skip().redact("")
    assert out == {"redacted_text": "", "entities": [], "categories": [], "count": 0}


# ── NLP models ────────────────────────────────────────────────


def _presidio():
    pytest.importorskip("presidio_analyzer")
    from admina.engines import presidio

    return presidio


FISCAL_CODE_TEXT = "Il codice fiscale è SMPPRV90A01Z404G, email prova@example.org"


def test_blank_italian_pipeline_needs_no_model():
    presidio = _presidio()
    engine = presidio.PresidioPIIEngine(nlp_models={"it": "blank"})
    assert engine.languages == ["it"]
    out = engine.redact("Mario Rossi scrive a prova@example.org")
    assert out["redacted_text"] == "Mario Rossi scrive a [EMAIL]"  # no NER: tokenizer only


def test_blank_pipelines_for_every_language():
    presidio = _presidio()
    engine = presidio.PresidioPIIEngine(nlp_models={"it": "blank", "en": "blank"})
    assert engine.languages == ["it", "en"]
    assert "[EMAIL]" in engine.redact("mail prova@example.org")["redacted_text"]


def test_installed_model_is_used_as_configured():
    presidio = _presidio()
    import spacy

    if not spacy.util.is_package("en_core_web_sm"):
        pytest.skip("en_core_web_sm not installed")
    engine = presidio.PresidioPIIEngine(nlp_models={"en": "en_core_web_sm"})
    assert engine.languages == ["en"]
    assert "[PERSON]" in engine.redact("Contact John Smith today")["redacted_text"]


def test_unknown_language_is_an_error():
    presidio = _presidio()
    with pytest.raises(ValueError, match="xq"):
        presidio.PresidioPIIEngine(nlp_models={"xq": "blank"})


def test_models_from_the_environment(monkeypatch):
    presidio = _presidio()
    monkeypatch.setenv("ADMINA_PRESIDIO_NLP_MODELS", "it:blank, en:blank")
    assert presidio.presidio_nlp_models() == {"it": "blank", "en": "blank"}
    assert presidio.get_presidio_pii_engine().languages == ["it", "en"]


@pytest.mark.parametrize("value", ["it", "it:", ":blank", "it:blank,it:blank"])
def test_malformed_environment_value_is_an_error(monkeypatch, value):
    presidio = _presidio()
    monkeypatch.setenv("ADMINA_PRESIDIO_NLP_MODELS", value)
    with pytest.raises(ValueError, match="ADMINA_PRESIDIO_NLP_MODELS"):
        presidio.presidio_nlp_models()


def test_models_from_admina_yaml(monkeypatch, tmp_path):
    presidio = _presidio()
    path = tmp_path / "admina.yaml"
    path.write_text("presidio:\n  nlp_models:\n    it: blank\n", encoding="utf-8")
    monkeypatch.delenv("ADMINA_PRESIDIO_NLP_MODELS", raising=False)
    monkeypatch.setenv("ADMINA_CONFIG", str(path))
    assert presidio.presidio_nlp_models() == {"it": "blank"}


def test_malformed_admina_yaml_is_an_error(monkeypatch, tmp_path):
    presidio = _presidio()
    path = tmp_path / "admina.yaml"
    path.write_text("presidio:\n  nlp_models: [it]\n", encoding="utf-8")
    monkeypatch.delenv("ADMINA_PRESIDIO_NLP_MODELS", raising=False)
    monkeypatch.setenv("ADMINA_CONFIG", str(path))
    with pytest.raises(ValueError, match="presidio.nlp_models"):
        presidio.presidio_nlp_models()


def test_default_models_are_those_installed(monkeypatch, tmp_path):
    presidio = _presidio()
    import spacy

    monkeypatch.delenv("ADMINA_PRESIDIO_NLP_MODELS", raising=False)
    monkeypatch.delenv("ADMINA_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    assert presidio.presidio_nlp_models() == {}
    installed = [
        lang
        for lang, model in (("en", "en_core_web_sm"), ("it", "it_core_news_sm"))
        if spacy.util.is_package(model)
    ]
    if not installed:
        pytest.skip("no default spaCy model installed")
    assert presidio.get_presidio_pii_engine(mask_style="typed").languages == installed


def test_fiscal_code_with_a_blank_pipeline():
    presidio = _presidio()
    engine = presidio.PresidioPIIEngine(nlp_models={"it": "blank"})
    out = engine.redact(FISCAL_CODE_TEXT)["redacted_text"]
    assert out == "Il codice fiscale è [CF], email [EMAIL]"


def test_overlapping_detections_are_masked_as_one_span(monkeypatch):
    presidio = _presidio()
    from presidio_analyzer import RecognizerResult

    engine = presidio.PresidioPIIEngine(nlp_models={"it": "blank"})
    text = "chiamate il +39 333 123 4567 oggi"
    found = [
        RecognizerResult("ORGANIZATION", 0, 19, 0.85),  # "chiamate il +39 333"
        RecognizerResult("PHONE_NUMBER", 12, 28, 0.75),  # "+39 333 123 4567"
    ]
    monkeypatch.setattr(engine._analyzer, "analyze", lambda text, language, entities: list(found))
    out = engine.redact(text)
    assert out["redacted_text"] == "[ORG] oggi"
    assert out["count"] == 1
    assert out["entities"][0]["start"] == 0 and out["entities"][0]["end"] == 28


def test_only_mapped_entity_types_are_requested(monkeypatch):
    presidio = _presidio()
    engine = presidio.PresidioPIIEngine(nlp_models={"it": "blank"})
    requested = []

    def analyze(text, language, entities=None):
        requested.append(entities)
        return []

    monkeypatch.setattr(engine._analyzer, "analyze", analyze)
    engine.redact("testo")
    assert requested == [list(presidio._PRESIDIO_TO_ADMINA)]


def test_text_with_many_dots_is_analyzed_quickly():
    import time

    presidio = _presidio()
    engine = presidio.PresidioPIIEngine(nlp_models={"it": "blank"})
    text = "a." * 32_000
    start = time.perf_counter()
    engine.redact(text)
    # Every recognizer of Presidio took about a minute on this text; the
    # mapped ones take a fraction of a second.
    assert time.perf_counter() - start < 5.0

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

"""Risk classification of EU AI Act descriptions written in other languages.

``classify_risk`` matches the English keyword lists as before, and the term
lists of :mod:`admina.domains.compliance.ai_act_terms` (Italian, French and
German phrases for Art. 5, the areas of Annex III and Art. 50) on whole
words of a normalised text. The caller can choose the languages and add
terms of its own.
"""

from __future__ import annotations

import pytest

from admina.domains.compliance.ai_act_terms import TERM_LANGUAGES, normalize_text
from admina.domains.compliance.eu_ai_act import EUAIActCompliance


def _classify(description: str, use_case: str = "", data_types=None, **kwargs) -> dict:
    return EUAIActCompliance(**kwargs).classify_risk(description, use_case, data_types or [])


def test_term_languages():
    assert {"it", "fr", "de"} <= set(TERM_LANGUAGES)


@pytest.mark.parametrize(
    ("text", "expected", "area"),
    [
        (
            "Software che analizza i curriculum dei candidati e propone una graduatoria",
            "high",
            "employment",
        ),
        ("Sistema di punteggio sociale dei cittadini", "unacceptable", "social_scoring"),
        (
            "Valutazione del merito creditizio per la concessione di prestiti",
            "high",
            "essential_services",
        ),
        ("Assistente virtuale che risponde alle domande dei cittadini", "limited", "interaction"),
        ("Logiciel de tri des CV pour le recrutement", "high", "employment"),
        ("Système de notation sociale", "unacceptable", "social_scoring"),
        ("Bewerbermanagement mit automatischer Vorauswahl von Bewerbungen", "high", "employment"),
        ("Chatbot für Bürgeranfragen", "limited", "interaction"),
    ],
)
def test_other_languages_are_classified(text, expected, area):
    result = _classify(text)
    assert result["risk_category"] == expected
    assert area in result["matched_areas"]


def test_the_english_keywords_keep_their_results():
    assert _classify("AI credit scoring for loan approvals")["risk_category"] == "high"
    assert _classify("Spam filter for emails", "email classification")["risk_category"] == (
        "minimal"
    )


def test_an_italian_text_without_a_term_stays_minimal():
    assert _classify("Filtro antispam per la posta elettronica")["risk_category"] == "minimal"


def test_terms_match_whole_words():
    # "asilo nido" (nursery) is not "asilo" (asylum) of Annex III point 7.
    assert normalize_text("Asilo  Nido") == "asilo nido"
    assert _classify("Prenotazione dei posti all'asilo nido comunale")["risk_category"] == (
        "minimal"
    )
    assert _classify("Gestione delle domande di asilo")["risk_category"] == "high"


def test_accents_and_typographic_apostrophes_are_normalised():
    assert normalize_text("Affidabilità dell’utente") == "affidabilita dell'utente"
    assert _classify("Supporto alle forze dell’ordine")["risk_category"] == "high"


def test_languages_can_be_narrowed():
    text = "Software che analizza i curriculum dei candidati"
    assert _classify(text, term_languages=["fr"])["risk_category"] == "minimal"
    assert _classify(text, term_languages=["it"])["risk_category"] == "high"


def test_unknown_language_is_an_error():
    with pytest.raises(ValueError, match="xx"):
        EUAIActCompliance(term_languages=["xx"])


def test_caller_terms_are_added():
    result = _classify(
        "Smistamento delle pratiche di sostegno al reddito",
        extra_terms={"high": {"essential_services": ["sostegno al reddito"]}},
    )
    assert result["risk_category"] == "high"
    assert {
        "lang": "custom",
        "risk": "high",
        "area": "essential_services",
        "term": "sostegno al reddito",
    } in result["matched_terms"]


def test_the_result_names_the_terms_and_keeps_its_fields():
    result = _classify("Logiciel de tri des CV pour le recrutement")
    assert result["risk_category"] == "high"
    assert {"level", "description", "action"} <= set(result)
    assert any(t["lang"] == "fr" and t["area"] == "employment" for t in result["matched_terms"])

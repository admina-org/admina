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


"""Admina — EU AI Act risk terms in languages other than English.

:data:`TERMS` holds, per language, phrases that point to a risk class of the
EU AI Act (Reg. (EU) 2024/1689): ``unacceptable`` (prohibited practices of
Art. 5), ``high`` (the areas of Annex III) and ``limited`` (the transparency
cases of Art. 50), each grouped by area. The English keyword lists of
:mod:`admina.domains.compliance.eu_ai_act` are matched as before, by
substring; these terms are matched on whole words of a normalised text
(:func:`normalize_text`): lower case, accents removed, typographic
apostrophes made straight, whitespace collapsed. Every language is matched
against every text, so a term is never a word that English uses with
another meaning ("police", "admission", "triage" alone). A term that ends with
``*`` matches any word that starts with it (``curricul*``: curriculum,
curricula).

The lists propose a class; they do not decide one. A person confirms the
classification of a system (Art. 6(3)). A caller adds terms of its own with
the ``extra_terms`` argument of
:class:`~admina.domains.compliance.eu_ai_act.EUAIActCompliance`.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cache

__all__ = [
    "RISK_ORDER",
    "TERMS",
    "TERM_LANGUAGES",
    "TermMatch",
    "find_terms",
    "normalize_text",
]

#: Risk classes the terms point to, from the most severe.
RISK_ORDER = ("unacceptable", "high", "limited")

#: {language: {risk class: {area: [term, ...]}}}
TERMS: dict[str, dict[str, dict[str, list[str]]]] = {
    "it": {
        "unacceptable": {
            "social_scoring": ["punteggio sociale", "credito sociale", "social scoring"],
            "biometric_identification": [
                "identificazione biometrica in tempo reale",
                "riconoscimento facciale in tempo reale",
                "sorveglianza di massa",
            ],
            "manipulation": ["manipolazione subliminale", "tecniche subliminali"],
            "predictive_policing": ["polizia predittiva"],
            "intimate_imagery": [
                "immagini intime non consensuali",
                "deepfake di nudo",
                "materiale pedopornografico sintetico",
            ],
        },
        "high": {
            "biometrics": [
                "identificazione biometrica",
                "categorizzazione biometrica",
                "riconoscimento facciale",
            ],
            "critical_infrastructure": [
                "infrastruttur* critic*",
                "rete elettrica",
                "approvvigionamento idrico",
                "traffico stradale",
            ],
            "education": [
                "procedura di ammissione",
                "ammissione all'universita",
                "ammissione ai corsi",
                "valutazione degli studenti",
                "risultati dell'apprendimento",
                "sorveglianza durante gli esami",
                "orientamento scolastico",
            ],
            "employment": [
                "curricul*",
                "selezione del personale",
                "selezione dei candidati",
                "graduatoria dei candidati",
                "reclutamento",
                "assunzion*",
                "valutazione delle prestazioni dei dipendenti",
                "licenziament*",
            ],
            "essential_services": [
                "merito creditizio",
                "affidabilita creditizia",
                "prestazioni sociali",
                "prestazioni assistenziali",
                "servizi di emergenza",
                "chiamate di emergenza",
                "triage ospedaliero",
                "triage al pronto soccorso",
                "assicurazion* sulla vita",
                "assicurazion* sanitari*",
            ],
            "law_enforcement": [
                "forze dell'ordine",
                "polizia",
                "indagini penali",
                "rischio di recidiva",
                "profilazione criminale",
            ],
            "migration": [
                "domande di asilo",
                "richiedent* asilo",
                "protezione internazionale",
                "controllo delle frontiere",
                "rilascio dei visti",
                "permess* di soggiorno",
            ],
            "justice_democracy": [
                "autorita giudiziari*",
                "sentenz*",
                "risoluzione delle controversie",
                "comportamento di voto",
                "esito delle elezioni",
            ],
        },
        "limited": {
            "interaction": ["chatbot", "assistente virtuale", "conversazional*"],
            "synthetic_content": [
                "generazione di contenuti",
                "contenuti sintetici",
                "testo generato",
            ],
            "deepfake": ["deepfake"],
            "emotion_recognition": ["riconoscimento delle emozioni"],
        },
    },
    "fr": {
        "unacceptable": {
            "social_scoring": ["notation sociale", "credit social", "social scoring"],
            "biometric_identification": [
                "identification biometrique en temps reel",
                "reconnaissance faciale en temps reel",
                "surveillance de masse",
            ],
            "manipulation": ["manipulation subliminale", "techniques subliminales"],
            "predictive_policing": ["police predictive"],
            "intimate_imagery": [
                "images intimes non consenties",
                "deepfake de nudite",
                "pedopornographi* synthetique",
            ],
        },
        "high": {
            "biometrics": [
                "identification biometrique",
                "categorisation biometrique",
                "reconnaissance faciale",
            ],
            "critical_infrastructure": [
                "infrastructure* critique*",
                "reseau electrique",
                "approvisionnement en eau",
                "trafic routier",
            ],
            "education": [
                "procedure d'admission",
                "admission a l'universite",
                "evaluation des eleves",
                "evaluation des etudiants",
                "acquis d'apprentissage",
                "surveillance des examens",
                "orientation scolaire",
            ],
            "employment": [
                "tri des cv",
                "analyse des cv",
                "curriculum vitae",
                "recrutement",
                "embauche",
                "selection des candidats",
                "tri des candidatures",
                "evaluation des performances des salaries",
                "licenciement*",
            ],
            "essential_services": [
                "solvabilite",
                "score de credit",
                "prestations sociales",
                "aide sociale",
                "services d'urgence",
                "appels d'urgence",
                "triage des patients",
                "assurance* vie",
                "assurance* sante",
            ],
            "law_enforcement": [
                "forces de l'ordre",
                "services de police",
                "enquetes penales",
                "risque de recidive",
                "profilage criminel",
            ],
            "migration": [
                "demandes d'asile",
                "demandeur* d'asile",
                "protection internationale",
                "controle des frontieres",
                "delivrance des visas",
                "titre* de sejour",
            ],
            "justice_democracy": [
                "autorite* judiciaire*",
                "decisions de justice",
                "reglement des litiges",
                "comportement electoral",
                "resultat des elections",
            ],
        },
        "limited": {
            "interaction": ["chatbot", "agent conversationnel", "assistant virtuel"],
            "synthetic_content": [
                "generation de contenu*",
                "contenu* synthetique*",
                "texte genere",
            ],
            "deepfake": ["deepfake", "hypertrucage"],
            "emotion_recognition": ["reconnaissance des emotions"],
        },
    },
    "de": {
        "unacceptable": {
            "social_scoring": ["sozialkredit*", "social scoring", "soziale bewertung"],
            "biometric_identification": [
                "biometrische echtzeit-fernidentifizierung",
                "gesichtserkennung in echtzeit",
                "massenuberwachung",
            ],
            "manipulation": ["unterschwellige manipulation", "unterschwellige techniken"],
            "predictive_policing": ["vorausschauende polizeiarbeit", "predictive policing"],
            "intimate_imagery": [
                "nicht einvernehmliche intime bilder",
                "nackt-deepfake*",
                "synthetische kinderpornografi*",
            ],
        },
        "high": {
            "biometrics": [
                "biometrische identifizierung",
                "biometrische kategorisierung",
                "gesichtserkennung",
            ],
            "critical_infrastructure": [
                "kritische* infrastruktur*",
                "stromnetz*",
                "wasserversorgung",
                "strassenverkehr",
            ],
            "education": [
                "zulassung",
                "bewertung von schuler*",
                "bewertung von studierenden",
                "lernergebniss*",
                "prufungsaufsicht",
                "prufungsuberwachung",
            ],
            "employment": [
                "lebenslauf",
                "lebenslaufe",
                "bewerb*",
                "personalauswahl*",
                "einstellung* von personal",
                "leistungsbeurteilung*",
                "kundigung*",
            ],
            "essential_services": [
                "kreditwurdigkeit*",
                "bonitatsprufung*",
                "sozialleistung*",
                "notrufe",
                "notdienst*",
                "notaufnahme-triage",
                "lebensversicherung*",
                "krankenversicherung*",
            ],
            "law_enforcement": [
                "strafverfolgung*",
                "polizei*",
                "ruckfallrisiko",
                "kriminalprofil*",
            ],
            "migration": [
                "asylantrag*",
                "asylbewerber*",
                "internationaler schutz",
                "grenzkontroll*",
                "visumantrag*",
                "aufenthaltstitel*",
            ],
            "justice_democracy": [
                "justizbehorde*",
                "gerichtsentscheidung*",
                "streitbeilegung",
                "wahlverhalten",
                "wahlergebnis*",
            ],
        },
        "limited": {
            "interaction": ["chatbot*", "virtuelle* assistent*", "dialogsystem*"],
            "synthetic_content": [
                "generierung von inhalten",
                "synthetische* inhalt*",
                "generierte* text*",
            ],
            "deepfake": ["deepfake*"],
            "emotion_recognition": ["emotionserkennung"],
        },
    },
}

#: Languages of :data:`TERMS`.
TERM_LANGUAGES: tuple[str, ...] = tuple(TERMS)

_APOSTROPHES = str.maketrans({"’": "'", "‘": "'", "ʼ": "'", "`": "'"})
_SPACES = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """*text* in lower case, without accents, with straight apostrophes and
    single spaces."""
    decomposed = unicodedata.normalize("NFKD", text.translate(_APOSTROPHES))
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return _SPACES.sub(" ", stripped.lower().replace("ß", "ss")).strip()


@dataclass(frozen=True)
class TermMatch:
    """A term found in a text."""

    lang: str
    risk: str
    area: str
    term: str

    def as_dict(self) -> dict[str, str]:
        return {"lang": self.lang, "risk": self.risk, "area": self.area, "term": self.term}


@cache
def _term_rx(term: str) -> re.Pattern[str]:
    stem = term.endswith("*")
    words = normalize_text(term.rstrip("*")).split(" ")
    body = r"\s+".join(re.escape(w) for w in words)
    tail = r"\w*" if stem else ""
    return re.compile(rf"(?<!\w){body}{tail}(?!\w)")


def find_terms(
    text: str,
    terms: Mapping[str, Mapping[str, Mapping[str, Iterable[str]]]],
) -> list[TermMatch]:
    """The terms of *terms* (``{lang: {risk: {area: [term, ...]}}}``) found
    in *text*, matched on whole words of its normalised form."""
    normalized = normalize_text(text)
    found: list[TermMatch] = []
    for lang, by_risk in terms.items():
        for risk, by_area in by_risk.items():
            for area, area_terms in by_area.items():
                for term in area_terms:
                    if _term_rx(term).search(normalized):
                        found.append(TermMatch(lang, risk, area, term))
    return found

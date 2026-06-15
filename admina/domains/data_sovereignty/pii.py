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

"""
Admina — PII Redaction Engine — Data Sovereignty domain
Bidirectional masking of sensitive data on requests and responses.
"""

import logging
import os
import re

# spaCy is part of the [nlp] extra. When absent, PIIRedactor falls back
# to regex-only mode (still covers EMAIL/PHONE/SSN/IBAN/IP/credit-card/EU IDs).
try:
    import spacy as _spacy
except ImportError:
    _spacy = None  # type: ignore[assignment]

logger = logging.getLogger("admina.pii_redactor")

# NLP model used for NER-based PII detection.
# Priority: admina.yaml `pii.ner_model` > ADMINA_SPACY_MODEL env var > default.
SPACY_MODEL = os.environ.get("ADMINA_SPACY_MODEL", "en_core_web_sm")

# Mapping from the short category names used in admina.yaml to PII_CATEGORIES keys.
# Allows the YAML list ["email", "ssn", ...] to toggle entries in PII_CATEGORIES.
_YAML_CATEGORY_MAP: dict[str, str] = {
    "email": "EMAIL",
    "phone": "PHONE",
    "credit_card": "CREDIT_CARD",
    "ssn": "SSN",
    "iban": "IBAN",
    "ip": "IP_ADDRESS",
    "person": "PERSON",
    "org": "ORG",
    "gpe": "GPE",
    "loc": "LOC",
    "dob": "DATE_OF_BIRTH",
    "it_codice_fiscale": "IT_CODICE_FISCALE",
    "es_dni": "ES_DNI_NIE",
    "es_nie": "ES_DNI_NIE",
    "de_personalausweis": "DE_PERSONALAUSWEIS",
}

# Categories of PII that can be individually configured
PII_CATEGORIES = {
    "PERSON": {"enabled": True, "mask": "[PERSON]"},
    "ORG": {"enabled": True, "mask": "[ORG]"},
    "GPE": {"enabled": True, "mask": "[LOCATION]"},  # Geopolitical entities
    "LOC": {"enabled": True, "mask": "[LOCATION]"},
    "EMAIL": {"enabled": True, "mask": "[EMAIL]"},
    "PHONE": {"enabled": True, "mask": "[PHONE]"},
    "CREDIT_CARD": {"enabled": True, "mask": "[CREDIT_CARD]"},
    "SSN": {"enabled": True, "mask": "[SSN]"},
    "IBAN": {"enabled": True, "mask": "[IBAN]"},
    "IP_ADDRESS": {"enabled": True, "mask": "[IP_ADDR]"},
    "DATE_OF_BIRTH": {"enabled": True, "mask": "[DOB]"},
    # EU national identifiers — opt-in but on by default to match the
    # framework's EU-first positioning.
    "IT_CODICE_FISCALE": {"enabled": True, "mask": "[CF]"},
    "ES_DNI_NIE": {"enabled": True, "mask": "[DNI]"},
    "DE_PERSONALAUSWEIS": {"enabled": False, "mask": "[AUSWEIS]"},  # off — ambiguous regex
}

# Regex patterns for PII not covered by spaCy NER
REGEX_PII_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "PHONE": re.compile(r"(?<!\d)(\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "IBAN": re.compile(
        r"\b[A-Z]{2}\d{2}\s?[\dA-Z]{4}\s?[\dA-Z]{4}\s?[\dA-Z]{4}(?:\s?[\dA-Z]{4}){0,4}\b"
    ),
    # IPv4 with proper octet validation (each octet 0-255). Avoids matching
    # version strings like 1.2.3.999 or build numbers > 255.
    "IP_ADDRESS": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    # Italian Codice Fiscale (16 chars: 6 letters + 2 digits + 1 letter +
    # 2 digits + 1 letter + 3 alphanumeric + 1 letter)
    "IT_CODICE_FISCALE": re.compile(
        r"\b[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b",
        re.IGNORECASE,
    ),
    # Spanish DNI/NIE: 8 digits + 1 letter (DNI) or X/Y/Z + 7 digits + letter (NIE)
    "ES_DNI_NIE": re.compile(
        r"\b(?:\d{8}|[XYZ]\d{7})[-\s]?[A-Z]\b",
        re.IGNORECASE,
    ),
    # German Personalausweis: 10 chars (alphanumeric, no I/O)
    # NB: deliberately conservative — exact format varies by issue date.
    "DE_PERSONALAUSWEIS": re.compile(r"\b[CFGHJKLMNPRTVWXYZ\d]{10}\b"),
}

# Context windows used to filter version-string false positives on IPv4.
# Looks at the ~24 chars preceding/following the candidate match.
_VERSION_PREFIX_RX = re.compile(
    r"\b(?:version|versione|versión|ver|v|release|build|revision|rev|"
    r"update|patch|firmware|api[\s-]?v)\.?\s*$",
    re.IGNORECASE,
)
_VERSION_SUFFIX_RX = re.compile(
    r"^\s*(?:released|build|revision|update|patch|published|"
    r"\(.*?\)|out|stable|rc\d|beta|alpha)",
    re.IGNORECASE,
)


def _luhn_valid(number: str) -> bool:
    """Return True if the digit string passes the Luhn checksum."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:  # shortest valid PAN length
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _is_real_ipv4(text: str, start: int, end: int) -> bool:
    """Heuristic: skip IP-shaped numbers that are clearly version strings.

    Returns True if the match at [start:end] looks like a network address,
    False if it appears in a version-number context (e.g. "version 1.2.3.4",
    "released 1.2.3.4", "v1.2.3.4 stable").
    """
    prefix = text[max(0, start - 24) : start]
    if _VERSION_PREFIX_RX.search(prefix):
        return False
    suffix = text[end : end + 24]
    if _VERSION_SUFFIX_RX.match(suffix):
        return False
    return True


# Per-category mask for the new EU IDs (used by PIIRedactor when not overridden)
_DEFAULT_EU_ID_MASKS = {
    "IT_CODICE_FISCALE": "[CF]",
    "ES_DNI_NIE": "[DNI]",
    "DE_PERSONALAUSWEIS": "[AUSWEIS]",
}


class PIIRedactor:
    """
    Bidirectional PII redaction engine.
    Uses spaCy NER + regex patterns for comprehensive coverage.

    Args:
        config: Optional PIIConfig (or any object with `.ner_model` / `.categories`
                attributes) loaded from admina.yaml.  When supplied, its values
                take precedence over the module-level defaults and env vars.
    """

    def __init__(self, config=None):
        # Resolve NLP model: config.ner_model > ADMINA_SPACY_MODEL env var > default
        model_name = getattr(config, "ner_model", None) or SPACY_MODEL
        if _spacy is None:
            logger.info(
                "spaCy not installed — PII redaction running in regex-only mode "
                "(install admina-framework[nlp] for NER-based detection)"
            )
            self.nlp = None
        else:
            try:
                self.nlp = _spacy.load(model_name)
                logger.info("[OK] spaCy model loaded: %s", model_name)
            except OSError:
                logger.warning(
                    "spaCy model '%s' not found — using regex-only mode "
                    "(run: python -m spacy download %s)",
                    model_name,
                    model_name,
                )
                self.nlp = None

        # Build active categories: start from PII_CATEGORIES defaults, then
        # disable any category not listed in config.categories (if provided).
        if config is not None and getattr(config, "categories", None) is not None:
            enabled_keys = {_YAML_CATEGORY_MAP.get(c.lower(), c.upper()) for c in config.categories}
            self._active_categories = {
                k: {**v, "enabled": k in enabled_keys} for k, v in PII_CATEGORIES.items()
            }
        else:
            self._active_categories = PII_CATEGORIES

        self.total_redacted: int = 0
        self.redactions_by_type: dict[str, int] = {}

    def redact(self, text: str, categories: dict | None = None) -> dict:
        """
        Redact PII from text.
        Returns: {redacted_text: str, entities: [...], count: int}
        """
        if not text:
            return {"redacted_text": text, "entities": [], "count": 0}

        active_categories = categories or self._active_categories
        entities_found = []
        redacted = text

        # Step 1 — regex-based detection (higher precision for structured PII)
        for cat_name, pattern in REGEX_PII_PATTERNS.items():
            cat_config = active_categories.get(cat_name, {})
            if not cat_config.get("enabled", True):
                continue
            mask = cat_config.get("mask", f"[{cat_name}]")

            # Find all matches; for IP_ADDRESS, drop version-string matches
            # (e.g. "version 1.2.3.4 released") to reduce false positives.
            matches = list(pattern.finditer(redacted))
            if cat_name == "IP_ADDRESS":
                matches = [m for m in matches if _is_real_ipv4(redacted, m.start(), m.end())]
            elif cat_name == "CREDIT_CARD":
                matches = [m for m in matches if _luhn_valid(m.group())]

            if not matches:
                continue

            for match in matches:
                entities_found.append(
                    {
                        "type": cat_name,
                        "start": match.start(),
                        "end": match.end(),
                        "original_length": match.end() - match.start(),
                        "method": "regex",
                    }
                )

            # Replace in reverse order to preserve byte offsets of earlier matches.
            for match in sorted(matches, key=lambda m: m.start(), reverse=True):
                redacted = redacted[: match.start()] + mask + redacted[match.end() :]

        # Step 2 — spaCy NER-based detection
        if self.nlp:
            doc = self.nlp(redacted)
            # Process entities in reverse order to maintain positions
            ner_entities = sorted(doc.ents, key=lambda e: e.start_char, reverse=True)
            for ent in ner_entities:
                cat_config = active_categories.get(ent.label_, {})
                if not cat_config.get("enabled", False):
                    continue
                mask = cat_config.get("mask", f"[{ent.label_}]")
                entities_found.append(
                    {
                        "type": ent.label_,
                        "start": ent.start_char,
                        "end": ent.end_char,
                        "original_length": ent.end_char - ent.start_char,
                        "method": "spacy_ner",
                    }
                )
                redacted = redacted[: ent.start_char] + mask + redacted[ent.end_char :]

        count = len(entities_found)
        if count > 0:
            self.total_redacted += count
            for e in entities_found:
                t = e["type"]
                self.redactions_by_type[t] = self.redactions_by_type.get(t, 0) + 1
            logger.info(
                "[REDACTED] %d PII entities: %s", count, [e["type"] for e in entities_found]
            )

        return {
            "redacted_text": redacted,
            "entities": entities_found,
            "count": count,
        }

    def get_stats(self) -> dict:
        return {
            "total_redacted": self.total_redacted,
            "redactions_by_type": self.redactions_by_type,
            "spacy_available": self.nlp is not None,
        }

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
"""Engine-aware detector adapters: normalise each detector to a uniform verdict.

Each adapter exposes ``.name``, ``.kind`` ("binary"|"pii"), ``.engines()`` (the
subset of ["python", "rust"] actually available), and ``.predict(engine, sample)``.
"""

from __future__ import annotations


def rust_available() -> bool:
    try:
        import admina_core  # noqa: F401

        return True
    except ImportError:
        return False


def presidio_available() -> bool:
    """True when presidio-analyzer is importable AND at least one Admina spaCy
    model is present (so the engine can actually be constructed)."""
    try:
        import importlib.util

        import spacy

        if importlib.util.find_spec("presidio_analyzer") is None:
            return False
        return spacy.util.is_package("en_core_web_sm") or spacy.util.is_package("it_core_news_sm")
    except ImportError:
        return False


class InjectionAdapter:
    name = "injection"
    kind = "binary"
    positive_label = "attack"

    def engines(self) -> list[str]:
        return ["python", "rust"] if rust_available() else ["python"]

    def predict(self, engine: str, sample: dict) -> dict:
        text = sample["text"]
        if engine == "rust":
            import admina_core

            return {"detected": bool(admina_core.RustFirewall().check(text).is_injection)}
        from admina.domains.agent_security.firewall import InjectionFirewall

        return {"detected": bool(InjectionFirewall().check(text)["is_injection"])}


class PiiAdapter:
    name = "pii"
    kind = "pii"

    def engines(self) -> list[str]:
        engs = ["python"]
        if rust_available():
            engs.append("rust")
        if presidio_available():
            engs.append("presidio")
        return engs

    def env_signature(self, engine: str) -> str | None:
        """Pin the measurement environment that changes the Python PII metrics.

        The Python redactor's recall and false-positive counts depend on
        whether spaCy NER is active: with the model loaded it runs in
        ``nlp:<model>@<version>`` mode (NER catches PERSON/ORG/GPE/LOC but also
        mis-fires on some non-English negatives — higher type coverage, more
        sample-level FPs); without the model it falls back to ``regex`` mode
        (regex-only, deterministic, fewer FPs). The model *version* is part of
        the signature because a model/lib upgrade can change NER behaviour while
        the name is unchanged, so the gate would otherwise compare numbers it
        cannot guarantee are from the same NER. The baseline records this
        signature so the gate verifies metrics only against the exact pinned
        environment. The Rust engine is regex-only and deterministic → no signature.
        """
        if engine == "presidio":
            from importlib.metadata import version

            from admina.engines.presidio import get_presidio_pii_engine

            langs = "+".join(get_presidio_pii_engine().languages)
            return f"presidio:{version('presidio-analyzer')}/{langs}"
        if engine != "python":
            return None
        from admina.domains.data_sovereignty.pii import SPACY_MODEL, PIIRedactor

        redactor = PIIRedactor()
        if redactor.nlp is None:
            return "regex"
        version = redactor.nlp.meta.get("version", "unknown")
        return f"nlp:{SPACY_MODEL}@{version}"

    def predict(self, engine: str, sample: dict) -> dict:
        text = sample["text"]
        if engine == "rust":
            import admina_core

            cats = admina_core.RustPiiScanner().redact(text).categories
        elif engine == "presidio":
            from admina.engines.presidio import get_presidio_pii_engine

            cats = [e["type"] for e in get_presidio_pii_engine().redact(text)["entities"]]
        else:
            from admina.domains.data_sovereignty.pii import PIIRedactor

            cats = [e["type"] for e in PIIRedactor().redact(text)["entities"]]
        # Canonicalise to UPPER_SNAKE: the Rust engine emits lowercase category
        # names (e.g. "email"), the Python engine UPPER (e.g. "EMAIL"). Note the
        # Rust scanner has no IBAN/codice-fiscale/DNI patterns — those expected
        # types stay undetected on the Rust engine (a measured coverage gap).
        return {"detected_types": {c.upper() for c in cats}}


class LoopAdapter:
    name = "loop"
    kind = "binary"
    positive_label = "loop"

    @staticmethod
    def _python_available() -> bool:
        try:
            from admina.domains.agent_security.loop_breaker import LoopBreaker  # noqa: F401

            return True
        except ImportError:  # numpy/sklearn live in the [proxy] extra
            return False

    def engines(self) -> list[str]:
        engines: list[str] = []
        if self._python_available():
            engines.append("python")
        if rust_available():
            engines.append("rust")
        return engines

    def predict(self, engine: str, sample: dict) -> dict:
        messages = sample["messages"]
        sid = str(sample["id"])
        if engine == "rust":
            import admina_core

            breaker = admina_core.RustLoopBreaker()
            tripped = any(breaker.check(sid, m)["is_loop"] for m in messages)
            return {"detected": bool(tripped)}
        from admina.domains.agent_security.loop_breaker import LoopBreaker

        breaker = LoopBreaker()
        tripped = any(breaker.check(sid, m)["is_loop"] for m in messages)
        return {"detected": bool(tripped)}


def all_detectors() -> list:
    return [InjectionAdapter(), PiiAdapter(), LoopAdapter()]


def get_detector(name: str):
    for d in all_detectors():
        if d.name == name:
            return d
    raise KeyError(name)

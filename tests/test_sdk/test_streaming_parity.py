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

"""Streaming-vs-batch redaction parity (spec §9).

Regex-detected PII must reach exact parity through the window; NER-detected
PII (PERSON/ORG) may show a bounded recall gap, measured here rather than
assumed. Pinned to the Python engine for deterministic masks.
"""

from __future__ import annotations

import pytest

from admina.engines import get_pii_engine
from admina.sdk.streaming import StreamRedactor

# Documented bound: at most this many NER entities may be missed by the
# windowed path relative to full-text redaction on the corpus below.
MAX_NER_RECALL_GAP = 2

_TEXT = (
    "Dear Angela Merkel, please email angela@example.com or call "
    "212-555-0147. Acme Corporation and Siemens will attend. "
    "Regards, Mario Rossi from Fabbrica Italiana."
)


def _stream_redact(text: str, window: int, chunk: int) -> str:
    engine = get_pii_engine("spacy-regex")
    r = StreamRedactor(engine, window_chars=window)
    out: list[str] = []
    for i in range(0, len(text), chunk):
        out.extend(r.feed(text[i : i + chunk]))
    tail, _ = r.finish()
    out.append(tail)
    return "".join(out)


def test_regex_pii_exact_parity(monkeypatch) -> None:
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    batch = get_pii_engine("spacy-regex").redact(_TEXT)["redacted_text"]
    streamed = _stream_redact(_TEXT, window=64, chunk=7)
    # EMAIL + PHONE are regex-detected → must match count exactly.
    for mask in ("[EMAIL]", "[PHONE]"):
        assert streamed.count(mask) == batch.count(mask)
    # And the raw values never leak in the streamed output.
    assert "angela@example.com" not in streamed
    assert "212-555-0147" not in streamed


def test_ner_recall_gap_within_bound(monkeypatch) -> None:
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    engine = get_pii_engine("spacy-regex")
    if not engine.get_stats().get("spacy_available", False):
        pytest.skip("spaCy NER model not installed; NER parity is not exercised")
    batch = engine.redact(_TEXT)["redacted_text"]
    streamed = _stream_redact(_TEXT, window=64, chunk=7)
    batch_ner = batch.count("[PERSON]") + batch.count("[ORG]")
    stream_ner = streamed.count("[PERSON]") + streamed.count("[ORG]")
    # Streaming may miss some NER context, never invent it.
    assert stream_ner <= batch_ner
    assert batch_ner - stream_ner <= MAX_NER_RECALL_GAP

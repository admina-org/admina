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

    with pytest.raises(ImportError, match=r"admina-framework\[presidio\]"):
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

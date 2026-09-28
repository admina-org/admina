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

"""``ADMINA_PII_MASK_STYLE``: ``typed`` (default) or ``omissis``.

``typed`` masks each span with its type (``[EMAIL]``, ``[PERSON]``, …).
``omissis`` masks each span with ``[OMISSIS]`` and, for the categories an
engine masks as a whole sentence (``sentence_categories``), the sentence
that holds the span; no type label is left in the text, in request
redaction, in responses and in streamed responses.
"""

from __future__ import annotations

import json
import re

import pytest

from admina.domains.data_sovereignty.masking import (
    OMISSIS,
    mask_omissis,
    normalize_mask_style,
    sentence_spans,
)
from admina.engines import get_pii_engine, pii_mask_style
from admina.sdk.streaming import StreamRedactor

TYPED_LABEL = re.compile(r"\[(?!OMISSIS\])[A-Z][A-Z0-9_]*\]")

EMAIL = "prova.esempio@example.com"
TEXT = f"Scrivere a {EMAIL} o chiamare il +39 333 123 4567 entro lunedì."
HEALTH = "Il paziente ha una diagnosi di diabete e segue una terapia."
NOTE = f"{HEALTH} Per informazioni scrivere a {EMAIL} oggi."


@pytest.fixture(autouse=True)
def _no_engine_settings(monkeypatch, tmp_path):
    for name in ("ADMINA_PII_ENGINE", "ADMINA_PII_MASK_STYLE", "ADMINA_CONFIG", "ADMINA_ENGINE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)


def _omissis(monkeypatch) -> None:
    monkeypatch.setenv("ADMINA_PII_MASK_STYLE", "omissis")


def _only_omissis(text: str) -> None:
    assert OMISSIS in text
    assert not TYPED_LABEL.search(text), text


# ── The setting ───────────────────────────────────────────────


def test_default_is_typed():
    assert pii_mask_style() == "typed"


@pytest.mark.parametrize("value", ["omissis", "OMISSIS", " Omissis "])
def test_environment(monkeypatch, value):
    monkeypatch.setenv("ADMINA_PII_MASK_STYLE", value)
    assert pii_mask_style() == "omissis"


def test_admina_yaml(monkeypatch, tmp_path):
    path = tmp_path / "admina.yaml"
    path.write_text("pii_mask_style: omissis\n", encoding="utf-8")
    monkeypatch.setenv("ADMINA_CONFIG", str(path))
    assert pii_mask_style() == "omissis"
    monkeypatch.setenv("ADMINA_PII_MASK_STYLE", "typed")
    assert pii_mask_style() == "typed"  # the environment wins


def test_unknown_style_stops_engine_selection(monkeypatch):
    monkeypatch.setenv("ADMINA_PII_MASK_STYLE", "stars")
    with pytest.raises(ValueError, match="typed.*omissis"):
        get_pii_engine()


def test_normalize():
    assert normalize_mask_style(None) == normalize_mask_style("") == "typed"
    with pytest.raises(ValueError):
        normalize_mask_style("custom")


# ── Built-in engines ──────────────────────────────────────────


def _builtin(name: str):
    try:
        return get_pii_engine(name)
    except ImportError as exc:
        pytest.skip(str(exc))


def test_spacy_regex_typed_is_unchanged():
    out = _builtin("spacy-regex").redact(TEXT)["redacted_text"]
    assert "[EMAIL]" in out and "[PHONE]" in out
    assert OMISSIS not in out


@pytest.mark.parametrize("name", ["spacy-regex", "presidio"])
def test_builtin_engine_omissis(monkeypatch, name):
    _omissis(monkeypatch)
    out = _builtin(name).redact(TEXT)
    _only_omissis(out["redacted_text"])
    assert EMAIL not in out["redacted_text"]
    assert out["count"] >= 2


def test_rust_scanner_omissis(monkeypatch):
    pytest.importorskip("admina_core")
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    _omissis(monkeypatch)
    engine = get_pii_engine("spacy-regex")
    assert engine.get_stats()["engine"] == "rust"
    out = engine.redact(f"mail {EMAIL}, card 4111 1111 1111 1111, ip 10.0.0.1")
    _only_omissis(out["redacted_text"])
    assert out["redacted_text"].count(OMISSIS) == 3


def test_placeholder_omissis_is_kept(monkeypatch):
    _omissis(monkeypatch)
    out = _builtin("spacy-regex").redact(f"Il nome è [OMISSIS], mail {EMAIL}")
    assert out["redacted_text"] == f"Il nome è {OMISSIS}, mail {OMISSIS}"


# ── Engines of other packages ─────────────────────────────────


def test_plugin_typed(example_pii_plugin):
    out = get_pii_engine("example-pii").redact(NOTE)["redacted_text"]
    assert out == (
        "Il paziente ha una [HEALTH] di [HEALTH] e segue una [HEALTH]. "
        "Per informazioni scrivere a [EMAIL] oggi."
    )


def test_plugin_omissis_masks_the_sentence(example_pii_plugin, monkeypatch):
    _omissis(monkeypatch)
    out = get_pii_engine("example-pii").redact(NOTE)
    assert out["redacted_text"] == f"{OMISSIS}. Per informazioni scrivere a {OMISSIS} oggi."
    assert out["count"] == 4
    assert out["categories"] == ["EMAIL", "HEALTH"]


def test_plugin_omissis_masks_every_sentence_with_a_term(example_pii_plugin, monkeypatch):
    _omissis(monkeypatch)
    text = "Primo ricovero a marzo. Nessuna novità.\nSecondo ricovero: aprile"
    out = get_pii_engine("example-pii").redact(text)["redacted_text"]
    assert out == f"{OMISSIS}. Nessuna novità.\n{OMISSIS}"


def test_plugin_sentences_from_the_engine(example_pii_plugin, monkeypatch):
    from example_pii_engine import ExamplePIIEngine

    from admina.engines import PIIEngineBridge

    class SemicolonSentences(ExamplePIIEngine):
        def sentences(self, text):
            spans, start = [], 0
            for part in text.split(";"):
                spans.append((start, start + len(part)))
                start += len(part) + 1
            return spans

    bridge = PIIEngineBridge(SemicolonSentences(), mask_style="omissis")
    out = bridge.redact("visita di controllo; diagnosi confermata; nulla da segnalare")
    assert out["redacted_text"] == f"visita di controllo; {OMISSIS}; nulla da segnalare"


# ── Masking helpers ───────────────────────────────────────────


def test_sentence_spans():
    text = "Primo punto. Secondo punto! Terzo?\nQuarto con l'art. 9 citato. Fine"
    parts = [text[a:b] for a, b in sentence_spans(text)]
    assert parts == [
        "Primo punto",
        "Secondo punto",
        "Terzo",
        "Quarto con l'art. 9 citato",
        "Fine",
    ]


def test_mask_omissis_merges_overlaps():
    text = "abc def ghi"
    assert mask_omissis(text, [(0, 3, "A"), (2, 7, "B")]) == f"{OMISSIS} ghi"
    assert mask_omissis(text, []) == text


# ── Through the gateway ───────────────────────────────────────


def test_gateway_request_and_response_omissis(example_pii_plugin, monkeypatch):
    from _gateway_stream import MockUpstream, settings, through

    _omissis(monkeypatch)
    completion = {
        "id": "c1",
        "object": "chat.completion",
        "model": "example-model",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": NOTE}, "finish_reason": "stop"}
        ],
    }
    upstream = MockUpstream([json.dumps(completion).encode()], content_type="application/json")
    body = {"model": "example-model", "messages": [{"role": "user", "content": NOTE}]}
    engine = get_pii_engine("example-pii")
    cfg = settings(PII_REDACTION_ENABLED=True)
    resp = through(upstream, body, cfg, state={"pii_redactor": engine})
    assert resp.status_code == 200
    (request,) = upstream.requests
    forwarded = json.loads(request.content)["messages"][0]["content"]
    returned = resp.json()["choices"][0]["message"]["content"]
    for text in (forwarded, returned):
        assert text == f"{OMISSIS}. Per informazioni scrivere a {OMISSIS} oggi."


def _sse(chunks: list[str]) -> list[bytes]:
    events = []
    for i, piece in enumerate(chunks):
        chunk = {
            "id": "c1",
            "object": "chat.completion.chunk",
            "model": "example-model",
            "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": None}],
        }
        events.append(f"data: {json.dumps(chunk)}\n\n".encode())
    last = {
        "id": "c1",
        "object": "chat.completion.chunk",
        "model": "example-model",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    }
    events.append(f"data: {json.dumps(last)}\n\n".encode())
    events.append(b"data: [DONE]\n\n")
    return events


def _streamed_text(resp) -> str:
    text = ""
    for line in resp.text.splitlines():
        if line.startswith("data: ") and line != "data: [DONE]":
            for choice in json.loads(line[6:]).get("choices", []):
                text += choice.get("delta", {}).get("content") or ""
    return text


@pytest.mark.parametrize("engine_name", ["spacy-regex", "example-pii"])
def test_gateway_stream_omissis(example_pii_plugin, monkeypatch, engine_name):
    from _gateway_stream import MockUpstream, settings, through

    _omissis(monkeypatch)
    pieces = [NOTE[i : i + 3] for i in range(0, len(NOTE), 3)]
    upstream = MockUpstream(_sse(pieces))
    body = {
        "model": "example-model",
        "stream": True,
        "messages": [{"role": "user", "content": "hi"}],
    }
    cfg = settings(PII_REDACTION_ENABLED=True)
    engine = get_pii_engine(engine_name)
    resp = through(upstream, body, cfg, stream_mode="governed", state={"pii_redactor": engine})
    assert resp.status_code == 200
    streamed = _streamed_text(resp)
    _only_omissis(streamed)
    assert EMAIL not in streamed
    if engine_name == "example-pii":
        assert streamed == f"{OMISSIS}. Per informazioni scrivere a {OMISSIS} oggi."


# ── StreamRedactor and whole sentences ────────────────────────


def _stream(redactor: StreamRedactor, text: str, size: int) -> list[str]:
    out: list[str] = []
    for i in range(0, len(text), size):
        out.extend(redactor.feed(text[i : i + size]))
    tail, _ = redactor.finish()
    return [*out, tail]


def test_stream_holds_a_sentence_until_it_is_masked(example_pii_plugin, monkeypatch):
    _omissis(monkeypatch)
    engine = get_pii_engine("example-pii")
    opening = "Nel corso della visita di controllo effettuata presso l'ambulatorio "
    text = f"Buongiorno a tutti. {opening}è emersa una diagnosi di diabete. Fine."
    parts = _stream(StreamRedactor(engine, window_chars=16), text, 2)
    assert "".join(parts) == engine.redact(text)["redacted_text"]
    assert "".join(parts) == f"Buongiorno a tutti. {OMISSIS}. Fine."
    assert not any("ambulatorio" in part for part in parts)


def test_stream_releases_text_past_the_hold_limit(example_pii_plugin, monkeypatch):
    _omissis(monkeypatch)
    engine = get_pii_engine("example-pii")
    text = "parola " * 200  # no sentence end
    redactor = StreamRedactor(engine, window_chars=16, max_hold_chars=256)
    emitted = []
    for i in range(0, len(text), 7):
        emitted.extend(redactor.feed(text[i : i + 7]))
        held = text[: i + 7][len("".join(emitted)) :]
        assert len(held) <= 256 + 7
    tail, _ = redactor.finish()
    assert "".join([*emitted, tail]) == text


def test_stream_typed_does_not_hold_sentences(example_pii_plugin):
    engine = get_pii_engine("example-pii")
    redactor = StreamRedactor(engine, window_chars=16)
    emitted = []
    for i in range(0, 200, 5):
        emitted.extend(redactor.feed(("parola " * 40)[i : i + 5]))
    assert "".join(emitted)  # released before the end


def test_hold_limit_is_at_least_the_window():
    with pytest.raises(ValueError, match="max_hold_chars"):
        StreamRedactor(object(), window_chars=64, max_hold_chars=32)

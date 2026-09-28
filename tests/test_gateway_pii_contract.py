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

"""The gateway's PII contract, for every PII engine and mask style.

Every built-in engine, the engines of the ``example-pii`` fixture
distribution and any engine installed in the ``admina.pii_engines`` group
get the same chat completion, in Italian, with synthetic personal data (a
fiscal code, an IBAN compact and spaced, an e-mail address, a phone number)
in a system message, a user message, a tool call, a tool result and a text
part. The gateway answers 200 and forwards the same JSON structure (keys,
roles, names, ids, the image part), with each text field replaced by the
engine's redaction of it, none of the synthetic values, and masks of the
mask style: typed masks, or only ``[OMISSIS]``.

Presidio runs with blank pipelines for Italian and English (no model), and
again with the NER models installed for each language.
"""

from __future__ import annotations

import json
import re

import pytest

pytest.importorskip("fastapi")

from _gateway_stream import MockUpstream, settings, through
from test_iban_it import spaced, synthetic_iban

from admina.engines import _PII_ENGINE_FACTORIES, get_pii_engine
from admina.engines.pii_plugins import plugin_engine_names

FISCAL_CODE = "SMPPRV90A01Z404G"
IBAN = synthetic_iban("IT", "Z" + "99999" + "99999" + "000000001234")
EMAIL = "prova.esempio@example.org"
PHONE = "+39 333 123 4567"
SYNTHETIC = [FISCAL_CODE, IBAN, spaced(IBAN), EMAIL, PHONE, "123 4567", "1234"]

MESSAGES = [
    {"role": "system", "content": "Sei un assistente. Rispondi in italiano, in modo sintetico."},
    {
        "role": "user",
        "content": (
            f"Buongiorno, il mio codice fiscale è {FISCAL_CODE}. Accreditate il rimborso "
            f"sull'IBAN {IBAN} oppure su {spaced(IBAN)}. Scrivete a {EMAIL}."
        ),
    },
    {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "cerca_pratica", "arguments": json.dumps({"email": EMAIL})},
            }
        ],
    },
    {
        "role": "tool",
        "tool_call_id": "call_1",
        "name": "cerca_pratica",
        "content": f"Pratica intestata al codice fiscale {FISCAL_CODE}, IBAN {spaced(IBAN)}.",
    },
    {
        "role": "user",
        "name": "utente_esempio",
        "content": [
            {"type": "text", "text": f"Oppure chiamate il {PHONE}, grazie."},
            {"type": "image_url", "image_url": {"url": "https://img.example/modulo.png"}},
        ],
    },
]

TYPED_LABEL = re.compile(r"\[(?!OMISSIS\])[A-Z][A-Z0-9_]*\]")

_COMPLETION = {
    "id": "c1",
    "object": "chat.completion",
    "model": "example-model",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
    ],
}


def _engine_names() -> list[str]:
    installed = [name for name in plugin_engine_names() if name not in _PII_ENGINE_FACTORIES]
    names = [*sorted(_PII_ENGINE_FACTORIES), "presidio-ner", "example-pii", "every-word"]
    return [*names, *installed]


def _presidio(mask_style: str, *, ner: bool):
    pytest.importorskip("presidio_analyzer")
    import spacy

    from admina.engines.presidio import PresidioPIIEngine

    models = {"it": "it_core_news_sm", "en": "en_core_web_sm"}
    if ner:
        models = {lang: m if spacy.util.is_package(m) else "blank" for lang, m in models.items()}
        if set(models.values()) == {"blank"}:
            pytest.skip("no spaCy model installed")
    else:
        models = dict.fromkeys(models, "blank")
    return PresidioPIIEngine(mask_style=mask_style, nlp_models=models)


@pytest.fixture
def case(request, example_pii_plugin, monkeypatch, tmp_path):
    """The engine of the case and its mask style."""
    name, mask_style = request.param
    for variable in ("ADMINA_PII_ENGINE", "ADMINA_CONFIG", "ADMINA_ENGINE"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ADMINA_PII_MASK_STYLE", mask_style)
    if name.startswith("presidio"):
        return _presidio(mask_style, ner=name == "presidio-ner"), mask_style
    return get_pii_engine(name), mask_style


_CASES = [(name, style) for name in _engine_names() for style in ("typed", "omissis")]


def _text_fields(messages: list[dict]) -> list[str]:
    texts = []
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            texts.extend(p["text"] for p in content if isinstance(p.get("text"), str))
        for call in message.get("tool_calls") or []:
            texts.append(call["function"]["arguments"])
    return texts


def _without_text(messages: list[dict]) -> list[dict]:
    """*messages* with every text field blanked: the structure to keep."""
    out = json.loads(json.dumps(messages))
    for message in out:
        if isinstance(message.get("content"), str):
            message["content"] = "·"
        elif isinstance(message.get("content"), list):
            for part in message["content"]:
                if isinstance(part.get("text"), str):
                    part["text"] = "·"
        for call in message.get("tool_calls") or []:
            call["function"]["arguments"] = "·"
    return out


@pytest.mark.parametrize("stream", [False, True], ids=["json", "stream"])
@pytest.mark.parametrize("case", _CASES, ids=[f"{n}-{s}" for n, s in _CASES], indirect=True)
def test_gateway_pii_contract(case, stream):
    engine, mask_style = case
    if stream:
        upstream = MockUpstream([b'data: {"choices": []}\n\n', b"data: [DONE]\n\n"])
    else:
        upstream = MockUpstream([json.dumps(_COMPLETION).encode()], content_type="application/json")
    body = {"model": "example-model", "messages": MESSAGES, "stream": stream}
    resp = through(
        upstream, body, settings(PII_REDACTION_ENABLED=True), state={"pii_redactor": engine}
    )

    assert resp.status_code == 200
    (request,) = upstream.requests
    forwarded = json.loads(request.content)["messages"]
    assert _without_text(forwarded) == _without_text(MESSAGES)
    assert _text_fields(forwarded) == [
        engine.redact(text)["redacted_text"] for text in _text_fields(MESSAGES)
    ]
    sent = json.dumps(forwarded, ensure_ascii=False)
    for value in SYNTHETIC:
        assert value not in sent, value
    masks = "".join(_text_fields(forwarded))
    if mask_style == "omissis":
        assert "[OMISSIS]" in masks
        assert not TYPED_LABEL.search(masks)
    else:
        assert TYPED_LABEL.search(masks)
        assert "[OMISSIS]" not in masks

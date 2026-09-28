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

"""PII redaction reads text values, never the structure around them.

- ``_deep_redact`` (MCP tool parameters and results, SDK agents) passes the
  values of a dict to the engine and keeps its keys, unless ``redact_keys``
  is set.
- The gateway passes the engine the text of each message: ``content`` (a
  string, or the ``text`` of each part), the reasoning and refusal text and
  tool call ``arguments``. Keys and the other fields (``role``, ``name``,
  ``tool_call_id``, ids, image parts, …) are forwarded as received.
- A placeholder already in the text (``[IBAN]``, ``[OMISSIS]``) stays as it is.
- A pipeline result that reports masked text without a list of messages
  blocks the request in every governance mode, with an error in the log.
"""

from __future__ import annotations

import json
import logging
import re

import pytest

pytest.importorskip("fastapi")

from _gateway_stream import MockUpstream, settings, through

from admina.domains.governance import (
    GovernanceResult,
    _deep_redact,
    redact_chat_params,
    redact_response_result,
)

_WORD = re.compile(r"\w+")


class EveryWord:
    """A PII engine that masks every word, as an over-eager NER model might."""

    def redact(self, text: str) -> dict:
        words = _WORD.findall(text)
        return {
            "redacted_text": _WORD.sub("[PERSON]", text),
            "entities": [{"type": "PERSON"} for _ in words],
            "count": len(words),
        }

    def get_stats(self) -> dict:
        return {}


class EmailOnly:
    """A PII engine that masks e-mail addresses only."""

    _rx = re.compile(r"[\w.]+@[\w.]+\.\w+")

    def redact(self, text: str) -> dict:
        found = self._rx.findall(text)
        return {
            "redacted_text": self._rx.sub("[EMAIL]", text),
            "entities": [{"type": "EMAIL"} for _ in found],
            "count": len(found),
        }

    def get_stats(self) -> dict:
        return {}


def _acc() -> dict:
    return {"redacted_text": "", "entities": [], "count": 0}


# ── _deep_redact: values only, keys on request ────────────────


def test_deep_redact_keeps_the_keys():
    params = {"name": "lookup", "arguments": {"customer": {"email": "a@b.example"}}}
    out = _deep_redact(params, _acc(), EveryWord())
    assert set(out) == {"name", "arguments"}
    assert set(out["arguments"]) == {"customer"}
    assert set(out["arguments"]["customer"]) == {"email"}
    assert out["arguments"]["customer"]["email"] == "[PERSON]@[PERSON].[PERSON]"


def test_deep_redact_passes_no_key_to_the_engine():
    seen: list[str] = []

    class Recording(EmailOnly):
        def redact(self, text: str) -> dict:
            seen.append(text)
            return super().redact(text)

    _deep_redact({"messages": [{"role": "user", "content": "hi"}]}, _acc(), Recording())
    assert sorted(seen) == ["hi", "user"]


def test_deep_redact_masks_keys_on_request():
    out = _deep_redact({"jane@x.example": "value"}, _acc(), EmailOnly(), redact_keys=True)
    assert out == {"[EMAIL]": "value"}


def test_response_result_keeps_the_keys():
    result = {"content": [{"type": "text", "text": "write to jane@x.example"}]}
    out, count = redact_response_result(result, EveryWord())
    assert count == 6  # the value "text" and five words
    assert set(out) == {"content"}
    assert set(out["content"][0]) == {"type", "text"}


# ── The gateway's chat messages ───────────────────────────────

_MESSAGES = [
    {"role": "system", "content": "Riassumi il documento allegato"},
    {
        "role": "user",
        "name": "example_user",
        "content": [
            {"type": "text", "text": "scrivi a jane@x.example"},
            {"type": "image_url", "image_url": {"url": "https://img.example/a.png"}},
        ],
    },
    {
        "role": "assistant",
        "content": None,
        "reasoning_content": "the user wants a summary",
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "lookup", "arguments": '{"q": "jane@x.example"}'},
            }
        ],
    },
    {"role": "tool", "tool_call_id": "call_1", "name": "lookup", "content": "found jane"},
]


def test_chat_params_keep_every_key_and_structural_value():
    out, acc = redact_chat_params({"messages": _MESSAGES}, EveryWord())
    assert set(out) == {"messages"}
    assert [set(m) for m in out["messages"]] == [set(m) for m in _MESSAGES]
    system, user, assistant, tool = out["messages"]
    assert [m["role"] for m in out["messages"]] == ["system", "user", "assistant", "tool"]
    assert user["name"] == "example_user"
    assert user["content"][0] == {
        "type": "text",
        "text": "[PERSON] [PERSON] [PERSON]@[PERSON].[PERSON]",
    }
    assert user["content"][1] == _MESSAGES[1]["content"][1]
    assert assistant["content"] is None
    call = assistant["tool_calls"][0]
    assert (call["id"], call["type"], call["function"]["name"]) == ("call_1", "function", "lookup")
    assert tool["tool_call_id"] == "call_1" and tool["name"] == "lookup"
    assert acc["count"] > 0


def test_chat_params_mask_the_text_of_each_message():
    out, acc = redact_chat_params({"messages": _MESSAGES}, EveryWord())
    system, user, assistant, tool = out["messages"]
    assert system["content"] == "[PERSON] [PERSON] [PERSON] [PERSON]"
    assert assistant["reasoning_content"] == "[PERSON] [PERSON] [PERSON] [PERSON] [PERSON]"
    assert assistant["tool_calls"][0]["function"]["arguments"] == (
        '{"[PERSON]": "[PERSON]@[PERSON].[PERSON]"}'
    )
    assert tool["content"] == "[PERSON] [PERSON]"


def test_chat_params_keep_text_the_engine_does_not_flag():
    out, acc = redact_chat_params({"messages": _MESSAGES}, EmailOnly())
    system, user, assistant, tool = out["messages"]
    assert system == _MESSAGES[0]
    assert user["content"][0]["text"] == "scrivi a [EMAIL]"
    assert assistant["tool_calls"][0]["function"]["arguments"] == '{"q": "[EMAIL]"}'
    assert tool == _MESSAGES[3]
    assert acc["count"] == 2


def test_chat_params_without_a_message_list_are_returned_unchanged():
    for params in ({}, {"messages": "not a list"}, {"messages": [None, 3, "x"]}):
        out, acc = redact_chat_params(params, EveryWord())
        assert out == params
        assert acc["count"] == 0


# ── Through the gateway ───────────────────────────────────────

_COMPLETION = {
    "id": "c1",
    "object": "chat.completion",
    "model": "example-model",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
    ],
}


def _json_upstream() -> MockUpstream:
    return MockUpstream([json.dumps(_COMPLETION).encode()], content_type="application/json")


def _forwarded(upstream: MockUpstream) -> dict:
    (request,) = upstream.requests
    return json.loads(request.content)


def test_gateway_forwards_the_message_structure_with_an_engine_that_masks_every_word():
    upstream = _json_upstream()
    body = {"model": "example-model", "messages": _MESSAGES}
    cfg = settings(PII_REDACTION_ENABLED=True)
    resp = through(upstream, body, cfg, state={"pii_redactor": EveryWord()})
    assert resp.status_code == 200
    forwarded = _forwarded(upstream)
    assert set(forwarded) == {"model", "messages"}
    assert [set(m) for m in forwarded["messages"]] == [set(m) for m in _MESSAGES]
    assert [m["role"] for m in forwarded["messages"]] == ["system", "user", "assistant", "tool"]
    assert forwarded["messages"][3]["tool_call_id"] == "call_1"
    assert "jane" not in json.dumps(forwarded["messages"])


def test_gateway_forwards_an_instruction_the_engine_does_not_flag():
    upstream = _json_upstream()
    messages = [
        {"role": "user", "content": "Riassumi il documento allegato, poi scrivi a a@b.example"}
    ]
    cfg = settings(PII_REDACTION_ENABLED=True)
    resp = through(
        upstream,
        {"model": "example-model", "messages": messages},
        cfg,
        state={"pii_redactor": EmailOnly()},
    )
    assert resp.status_code == 200
    assert _forwarded(upstream)["messages"] == [
        {"role": "user", "content": "Riassumi il documento allegato, poi scrivi a [EMAIL]"}
    ]


class _Recorder:
    """A forensic store that keeps the request records."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, event: dict) -> dict:
        if event["event_type"] != "gateway_response":
            self.events.append(event)
        return {"record_hash": "0" * 64}


def _pipeline_without_messages(monkeypatch, redacted_body: object) -> None:
    """The pipeline reports masked text, with *redacted_body* as its result."""
    from admina.proxy.api import gateway

    async def pipeline(**kwargs):
        return GovernanceResult(
            checks={"pii_redaction": {"count": 1, "entities": []}},
            redacted_body=redacted_body,
            gov_response=type("R", (), {"action": "ALLOW", "risk_level": "LOW"})(),
        )

    monkeypatch.setattr(gateway, "run_pipeline", pipeline)


@pytest.mark.parametrize(
    "redacted_body",
    [{"params": {}}, {"params": {"messages": "hello"}}, {"params": None}, None, ["hello"]],
    ids=["no-messages", "messages-not-a-list", "params-not-an-object", "no-body", "body-a-list"],
)
@pytest.mark.parametrize("mode", ["enforce", "observe"])
@pytest.mark.parametrize("stream", [False, True])
def test_gateway_blocks_when_the_redaction_result_has_no_messages(
    monkeypatch, caplog, stream, mode, redacted_body
):
    _pipeline_without_messages(monkeypatch, redacted_body)
    upstream = _json_upstream()
    recorder = _Recorder()
    body = {"model": "example-model", "messages": [{"role": "user", "content": "hello"}]}
    cfg = settings(PII_REDACTION_ENABLED=True, ADMINA_GOVERNANCE_MODE=mode)
    with caplog.at_level(logging.ERROR, logger="admina.proxy"):
        resp = through(upstream, {**body, "stream": stream}, cfg, state={"forensic_box": recorder})
    assert upstream.requests == []
    assert resp.status_code == 200
    assert resp.headers["x-admina-action"] == "BLOCK"
    if stream:
        assert '"finish_reason":"content_filter"' in resp.text
    else:
        assert resp.json()["choices"][0]["finish_reason"] == "content_filter"
    (event,) = recorder.events
    assert event["action"] == "BLOCK"
    assert event["risk_level"] == "HIGH"
    assert event["checks"]["pipeline"] == {"action": "ERROR", "error": "redacted_messages_missing"}
    assert event["checks"]["pii_redaction"]["count"] == 1
    assert "would_action" not in event
    assert any("messages" in r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR)


def test_gateway_answers_403_when_the_redaction_result_has_no_messages(monkeypatch):
    _pipeline_without_messages(monkeypatch, {"params": {}})
    upstream = _json_upstream()
    body = {"model": "example-model", "messages": [{"role": "user", "content": "hello"}]}
    cfg = settings(PII_REDACTION_ENABLED=True, ADMINA_GATEWAY_BLOCK_STATUS=403)
    resp = through(upstream, body, cfg)
    assert upstream.requests == []
    assert resp.status_code == 403
    assert resp.headers["x-admina-action"] == "BLOCK"
    assert resp.json()["error"]["code"] == "governance_blocked"
    assert resp.json()["error"]["categories"] == []


# ── Placeholders stay as they are ─────────────────────────────


def _spacy_regex():
    from admina.domains.data_sovereignty.pii import PIIRedactor

    redactor = PIIRedactor()
    if redactor.nlp is None:
        pytest.skip("spaCy model not installed: the regex-only engine masks no placeholder")
    return redactor


@pytest.mark.parametrize(
    "text",
    [
        "Pay to [IBAN] today",
        "Bonifico su [IBAN] e scrivi a [EMAIL]",
        "Il nome è [OMISSIS], residente a [LOCATION]",
    ],
)
def test_spacy_regex_keeps_placeholders(text):
    out = _spacy_regex().redact(text)["redacted_text"]
    for placeholder in re.findall(r"\[[A-Z]+\]", text):
        assert placeholder in out
    assert "[[" not in out


def test_a_span_is_reduced_to_its_parts_outside_the_placeholders():
    from admina.domains.data_sovereignty.masking import outside_placeholders, placeholder_spans

    text = "Mario [PERSON] e [EMAIL] oggi"
    spans = placeholder_spans(text)
    assert spans == [(6, 14), (17, 24)]
    assert outside_placeholders(0, len(text), spans, text) == [(0, 5), (15, 16), (25, 29)]
    assert outside_placeholders(7, 13, spans, text) == []  # inside [PERSON]
    assert outside_placeholders(0, 14, spans, text) == [(0, 5)]
    assert outside_placeholders(25, 29, spans, text) == [(25, 29)]
    assert outside_placeholders(0, 5, [], "Mario") == [(0, 5)]
    assert outside_placeholders(0, 3, [], " , ") == []

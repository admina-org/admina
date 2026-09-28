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

"""``request_sha256`` of the gateway request record.

The SHA-256 of the RFC 8785 (JCS) canonical form of the ``messages`` array
as forwarded upstream. The vectors of ``tests/fixtures/jcs_vectors.json``
hold, for each array, the canonical text written by hand and the SHA-256 of
its UTF-8 bytes, so that other implementations can check against them.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from _gateway_stream import EMAIL, MockUpstream, settings, through

from admina.core.jcs import canonicalize
from admina.proxy.gateway_outcome import messages_sha256

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "jcs_vectors.json").read_text(encoding="utf-8")
)["vectors"]
IDS = [vector["name"] for vector in VECTORS]
HEX64 = "0123456789abcdef"


class _Recorder:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, event: dict) -> dict:
        self.events.append(event)
        return {"record_hash": "0" * 64}


def _completion() -> MockUpstream:
    body = {
        "id": "c1",
        "object": "chat.completion",
        "model": "example-model",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
        ],
    }
    return MockUpstream([json.dumps(body).encode()], content_type="application/json")


def _send(messages, **over):
    upstream = _completion()
    recorder = _Recorder()
    body = {"model": "example-model", "messages": messages}
    resp = through(upstream, body, settings(**over), state={"forensic_box": recorder})
    request_record = next(e for e in recorder.events if e["event_type"] == "gateway_request")
    return resp, upstream, request_record


def test_vectors_cover_the_required_shapes():
    assert {"empty", "text", "text_parts", "tool_calls", "unicode", "numbers"} <= set(IDS)
    for vector in VECTORS:
        assert len(vector["sha256"]) == 64 and set(vector["sha256"]) <= set(HEX64)


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_vector_canonical_bytes_and_digest(vector):
    canonical = canonicalize(vector["messages"])
    assert canonical == vector["jcs"].encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == vector["sha256"]
    assert messages_sha256(vector["messages"]) == vector["sha256"]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_request_record_hashes_the_forwarded_messages(vector):
    resp, upstream, request_record = _send(vector["messages"])
    assert resp.status_code == 200
    forwarded = json.loads(upstream.requests[0].content)["messages"]
    assert forwarded == vector["messages"]
    assert request_record["request_sha256"] == vector["sha256"]


def test_blocked_request_hashes_the_messages_received():
    messages = [{"role": "user", "content": "INJECT something"}]
    resp, upstream, request_record = _send(messages)
    assert upstream.requests == []
    assert request_record["action"] == "BLOCK"
    assert request_record["request_sha256"] == messages_sha256(messages)


def test_redacted_messages_are_hashed_as_forwarded():
    messages = [{"role": "user", "content": f"Write to {EMAIL} today."}]
    resp, upstream, request_record = _send(messages, PII_REDACTION_ENABLED=True)
    forwarded = json.loads(upstream.requests[0].content)["messages"]
    assert forwarded != messages
    assert request_record["request_sha256"] == hashlib.sha256(canonicalize(forwarded)).hexdigest()


@pytest.mark.parametrize(
    "value",
    [
        "\ud800",  # unpaired surrogate: not a JCS string
        2**53 + 1,  # an integer no double holds exactly
    ],
    ids=["lone-surrogate", "large-integer"],
)
def test_messages_without_a_canonical_form_have_no_hash(value):
    assert messages_sha256([{"role": "user", "content": "hi", "extra": value}]) is None


def test_messages_nested_beyond_the_recursion_limit_have_no_hash():
    # Python 3.12 and later parse JSON nested deeper than the interpreter's
    # recursion limit, which the canonical form is written within.
    nested: list = []
    for _ in range(sys.getrecursionlimit() + 100):
        nested = [nested]
    assert messages_sha256([{"role": "user", "content": nested}]) is None


def test_request_without_a_canonical_form_is_still_forwarded():
    messages = [{"role": "user", "content": "hi", "extra": 2**53 + 1}]
    resp, upstream, request_record = _send(messages)
    assert resp.status_code == 200
    assert len(upstream.requests) == 1
    assert request_record["request_sha256"] is None

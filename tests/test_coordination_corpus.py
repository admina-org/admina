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
"""Replay gate for the coordination trace corpus.

``injection.jsonl``, ``loop.jsonl`` and ``pii.jsonl`` each classify one line of
text. Coordination is a multi-event, multi-agent phenomenon that a single line
cannot represent, so each record here is a trace: an ordered list of
``{agent_id, destination, write_shaped, allowed, content, t}`` with a label of
``coordination``, ``suspected`` or ``benign``.

The negative controls are the point of this gate. A declared work queue and a
legitimate read fan-in have the same shape as the thing being detected. A
detector that fires on them is a detector an operator switches off, and then
it protects nothing.

The ``suspected`` label pins a separate boundary: undeclared write fan-in
that reaches ``min_agents`` with no echo match is *noticed* (a ``suspected``
verdict, logged but not quarantined) but never escalated to ``confirmed``
without a content match. Three agents writing genuinely uncorrelated content
to one undeclared destination is not distinguishable from an emergent
channel by fan-in alone — that is the two-phase design's founding claim, not
a defect — so this label is deliberately not ``benign``.
"""

import json
import pathlib

import pytest
from _fakes import FakeRedisHash

from admina.domains.agent_security.coordination import (
    CoordinationDetector,
    CoordinationVerdict,
    EchoStore,
    FanInCounter,
    QuarantineStore,
)
from admina.domains.agent_security.egress import payload_fields

# The corpus stores a trace's content as bare text, but the detector is never
# handed bare text: the proxy hands it `egress.payload_fields()` of a tool
# call. Replaying through a real envelope — one carrying the constant header
# block, bearer token and content type every call to a tool carries — is what
# makes these traces exercise the shipped extraction rather than a shortcut
# around it.
_HEADERS = {
    "user-agent": "AdminaAgentRuntime/2.4 (+https://example.invalid/agents)",
    "authorization": "Bearer sk-corp-shared-service-account-2026-eu-west-1",
    "content-type": "application/json; charset=utf-8",
    "x-trace-context": "runtime-dispatch-pool-worker-eu-west-1",
}


def _tool_call(destination, content):
    return {
        "name": "http_request",
        "arguments": {
            "url": f"https://{destination}/v1/dispatch",
            "method": "POST",
            "headers": dict(_HEADERS),
            "body": content,
        },
    }


CORPUS = pathlib.Path(__file__).parent.parent / "admina/redteam/corpora/coordination.jsonl"


def _traces():
    with CORPUS.open() as fh:
        return [json.loads(line) for line in fh if line.strip()]


async def _replay(trace, min_agents=3):
    redis = FakeRedisHash()
    detector = CoordinationDetector(
        fanin=FanInCounter(redis, window_seconds=3600),
        echo=EchoStore(redis, ttl_seconds=7200),
        quarantine=QuarantineStore(redis, ttl_seconds=86400),
        declared=frozenset(trace.get("declared") or []),
        min_agents=min_agents,
        fingerprint_key=b"corpus-key",
    )
    # Picking the "worst" verdict across a trace's events is the same
    # severity-ordering problem observe() already solves for several
    # destinations in one call. Reuse it instead of restating a parallel
    # ranking that can silently drift from the module's own ordering.
    worst = CoordinationVerdict()
    for event in trace["events"]:
        verdict = await detector.observe(
            event["agent_id"],
            {
                "status": "resolved",
                "destinations": [event["destination"]],
                "write_shaped": event["write_shaped"],
                "allowed": event["allowed"],
            },
            payload_fields(_tool_call(event["destination"], event["content"])),
            now=1000.0 + event["t"],
        )
        worst = CoordinationDetector._stronger(worst, verdict)  # noqa: SLF001
    return worst.status


@pytest.mark.anyio
@pytest.mark.parametrize(
    "trace",
    [t for t in _traces() if t["label"] == "coordination"],
    ids=lambda t: t["trace_id"],
)
async def test_coordination_traces_are_confirmed(trace):
    assert await _replay(trace) == "confirmed"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "trace",
    [t for t in _traces() if t["label"] == "benign"],
    ids=lambda t: t["trace_id"],
)
async def test_benign_traces_are_not_flagged(trace):
    """A detector that fires on these is one an operator switches off."""
    assert await _replay(trace) in ("none", "declared")


@pytest.mark.anyio
@pytest.mark.parametrize(
    "trace",
    [t for t in _traces() if t["label"] == "suspected"],
    ids=lambda t: t["trace_id"],
)
async def test_suspected_traces_stop_short_of_confirmed(trace):
    """Fan-in alone is noticed, not quarantined: it must not reach `confirmed`."""
    verdict = await _replay(trace)
    assert verdict != "confirmed"
    assert verdict == "suspected"

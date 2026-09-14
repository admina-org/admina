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
``coordination`` or ``benign``.

The negative controls are the point of this gate. A declared work queue and a
legitimate read fan-in have the same shape as the thing being detected. A
detector that fires on them is a detector an operator switches off, and then
it protects nothing.
"""

import json
import pathlib

import pytest
from _fakes import FakeRedisHash

from admina.domains.agent_security.coordination import (
    CoordinationDetector,
    EchoStore,
    FanInCounter,
    QuarantineStore,
)

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
    worst = "none"
    rank = {"none": 0, "declared": 0, "degraded": 1, "suspected": 2, "confirmed": 3}
    for event in trace["events"]:
        verdict = await detector.observe(
            event["agent_id"],
            {
                "status": "resolved",
                "destinations": [event["destination"]],
                "write_shaped": event["write_shaped"],
                "allowed": event["allowed"],
            },
            event["content"],
            now=1000.0 + event["t"],
        )
        if rank[verdict.status] > rank[worst]:
            worst = verdict.status
    return worst


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

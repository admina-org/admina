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

"""Smoke test for the canonical governance pipeline at admina.domains.governance."""

from __future__ import annotations

import asyncio

from admina.domains.governance import run_pipeline


class _FW:  # noqa: D401
    def check(self, t):
        return {"is_injection": False, "risk_level": "low"}


class _PII:
    def redact(self, t):
        return {"redacted_text": t, "entities": [], "count": 0}


class _Loop:
    def check(self, s, c):
        return {"is_loop": False, "similarity": 0.0}


def test_canonical_pipeline_allows_clean_request():
    res = asyncio.run(
        run_pipeline(
            body={"params": {"content": "hello"}},
            content_str="hello",
            session_id="s",
            agent_id="a",
            request_id="r",
            params={"content": "hello"},
            firewall=_FW(),
            pii_redactor=_PII(),
            loop_breaker=_Loop(),
            governance_guards=[],
        )
    )
    assert res.action.value == "allow"
    assert res.gov_response.action == "ALLOW"

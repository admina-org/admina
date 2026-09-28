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

"""The forensic chain across restarts.

A restarted store resumes at the record after the last one, with a signed
state that verifies, whatever number of writers were recording before and
after. A record written just before the process stopped, when its chain
state was not saved yet, is taken over at startup when it verifies.
"""

from __future__ import annotations

import asyncio
import secrets
import threading
from pathlib import Path

import pytest
from _forensic_chain import STATE, STATE_SIG, load, record_files

from admina.domains.compliance.forensic import ForensicBlackBox, verify_directory


@pytest.fixture
def key(monkeypatch) -> str:
    for name in ("ADMINA_FORENSIC_STATE_KEY", "ADMINA_FORENSIC_STATE_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    return "canary-" + secrets.token_hex(16)


def _write_concurrently(box: ForensicBlackBox, writers: int, each: int, tag: str) -> None:
    def work(w: int) -> None:
        for i in range(each):
            box.record({"event_id": f"{tag}-{w}-{i}", "action": "ALLOW"})

    threads = [threading.Thread(target=work, args=(w,)) for w in range(writers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def _sequence_numbers(base: Path) -> list[int]:
    return [load(p)["sequence_number"] for p in record_files(base)]


def test_restarts_with_concurrent_writers_leave_no_gap(tmp_path, key):
    base = tmp_path / "forensic"
    total = 0
    for run in range(3):
        box = ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key)
        assert box.chain_status == "ok"
        assert box.record_count == total
        _write_concurrently(box, writers=8, each=5, tag=f"run{run}")
        total += 40
    assert _sequence_numbers(base) == list(range(1, total + 1))
    result = verify_directory(base, state_key=key)
    assert result["valid"] is True
    assert result["signed"] == total
    assert (
        asyncio.run(
            ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key).verify_chain()
        )["valid"]
        is True
    )


def test_a_record_written_after_the_last_saved_state_is_taken_over(tmp_path, key, caplog):
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key)
    for i in range(3):
        box.record({"event_id": f"e{i}"})
    saved = (base / STATE).read_bytes(), (base / STATE_SIG).read_bytes()
    box.record({"event_id": "e3"})
    # The process stopped after record 4 was written, before its state was.
    (base / STATE).write_bytes(saved[0])
    (base / STATE_SIG).write_bytes(saved[1])

    restarted = ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key)

    assert restarted.chain_status == "ok"
    assert restarted.record_count == 4
    assert restarted.record({"event_id": "e4"})["sequence_number"] == 5
    assert _sequence_numbers(base) == [1, 2, 3, 4, 5]
    assert verify_directory(base, state_key=key)["valid"] is True


def test_a_record_after_the_saved_state_that_does_not_verify_is_not_taken_over(tmp_path, key):
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key)
    for i in range(3):
        box.record({"event_id": f"e{i}"})
    head = record_files(base)[-1]
    # A record 4 that no store with the key wrote.
    other = ForensicBlackBox(filesystem_dir=str(tmp_path / "other"), state_signing_key="k2")
    for i in range(4):
        other.record({"event_id": f"x{i}"})
    (head.parent / "00000004.json").write_bytes(record_files(tmp_path / "other")[-1].read_bytes())

    restarted = ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key)

    assert restarted.chain_status == "invalid"
    assert restarted.record_count == 3


def _serve_concurrently(count: int):
    """Start the proxy, send *count* chat completions at once, stop it."""
    import httpx
    from _proxy_app import CHAT, upstream

    from admina.proxy import main as proxy_main

    async def go():
        async with proxy_main.lifespan(proxy_main.app):
            state = proxy_main.app.state.proxy
            await state.gateway_http_client.aclose()
            state.gateway_http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
            transport = httpx.ASGITransport(app=proxy_main.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                responses = await asyncio.gather(*(client.request(**CHAT) for _ in range(count)))
            return responses, state.forensic_box.chain_status

    return asyncio.run(go())


def test_the_proxy_resumes_the_chain_after_a_restart(tmp_path, key, monkeypatch):
    pytest.importorskip("fastapi")
    from _proxy_app import isolate

    from admina.proxy import main as proxy_main

    base = tmp_path / "forensic"
    monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY", key)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    isolate(monkeypatch, forensic_backend="filesystem", forensic_dir=str(base))

    for _ in range(2):
        responses, chain = _serve_concurrently(8)
        assert [r.status_code for r in responses] == [200] * 8
        assert chain == "ok"
    # Two records (request and response) per call, eight calls per run.
    assert _sequence_numbers(base) == list(range(1, 33))
    assert verify_directory(base, state_key=key)["valid"] is True
    assert len((base / STATE_SIG).read_text()) == 64

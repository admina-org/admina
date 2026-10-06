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

"""What happens when a forensic record cannot be written.

The store's fail mode: ``open`` (the default) logs the failure and goes on
without the record; ``closed`` raises :class:`ForensicWriteError`. Either
way the chain does not advance past a record that was not written.

The proxy (``ADMINA_FORENSIC_FAIL_MODE``): in ``closed`` mode a request whose
record is not written is answered 503 and never forwarded (gateway, /mcp),
and /api/v1/validate answers 503 while the store does not accept records; in
``open`` mode the request is served. ``/health`` reports ``forensic_writable``
and a ``degraded`` status. A filesystem or S3 backend that cannot be opened
stops the proxy at startup in ``closed`` mode; in ``open`` mode the proxy
starts with a store that records nothing, never with an in-memory one.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import secrets

import pytest
from _forensic_chain import STATE, MemoryBucket, S3Error, record_files

from admina.domains.compliance.forensic import ForensicBlackBox, ForensicWriteError

root_only = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root writes to any directory"
)


def _no_space(monkeypatch) -> None:
    """Every fsync fails as on a full disk."""

    def fsync(fd: int) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "fsync", fsync)


# ── Store ─────────────────────────────────────────────────────


def test_fail_mode_defaults_to_open(tmp_path):
    assert ForensicBlackBox(filesystem_dir=str(tmp_path)).fail_mode == "open"


def test_an_unknown_fail_mode_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="fail_mode"):
        ForensicBlackBox(filesystem_dir=str(tmp_path), fail_mode="sometimes")


def test_open_mode_logs_a_full_disk_and_goes_on(tmp_path, monkeypatch, caplog):
    box = ForensicBlackBox(filesystem_dir=str(tmp_path))
    box.record({"event_id": "e1"})
    _no_space(monkeypatch)

    with caplog.at_level(logging.ERROR, logger="admina.forensic_blackbox"):
        result = box.record({"event_id": "e2"})

    assert result == {
        "sequence_number": None,
        "record_hash": None,
        "previous_hash": None,
        "stored": False,
    }
    assert box.record_count == 1
    assert box.accepting_records() is False
    assert any("ENOSPC" in r.getMessage() or "No space" in r.getMessage() for r in caplog.records)


def test_closed_mode_raises_on_a_full_disk(tmp_path, monkeypatch):
    box = ForensicBlackBox(filesystem_dir=str(tmp_path), fail_mode="closed")
    box.record({"event_id": "e1"})
    _no_space(monkeypatch)

    with pytest.raises(ForensicWriteError) as excinfo:
        box.record({"event_id": "e2"})
    assert isinstance(excinfo.value.__cause__, OSError)
    assert box.record_count == 1
    assert len(record_files(tmp_path)) == 1


def test_a_write_that_works_again_is_accepted_again(tmp_path, monkeypatch):
    box = ForensicBlackBox(filesystem_dir=str(tmp_path), fail_mode="closed")
    with monkeypatch.context() as m:
        _no_space(m)
        with pytest.raises(ForensicWriteError):
            box.record({"event_id": "e1"})
    assert box.accepting_records() is False
    assert box.record({"event_id": "e2"})["sequence_number"] == 1
    assert box.accepting_records() is True
    assert asyncio.run(box.verify_chain())["valid"] is True


@root_only
def test_a_read_only_directory(tmp_path):
    directory = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(directory), fail_mode="closed")
    directory.chmod(0o500)
    try:
        with pytest.raises(ForensicWriteError):
            box.record({"event_id": "e1"})
        assert box.writable() is False
    finally:
        directory.chmod(0o700)


def test_the_memory_store_never_fails(tmp_path):
    box = ForensicBlackBox(fail_mode="closed")
    result = box.record({"event_id": "e1"})
    assert result["sequence_number"] == 1
    assert result["stored"] is False
    assert box.accepting_records() is True


# ── Proxy ─────────────────────────────────────────────────────


@pytest.fixture
def proxy_deps():
    pytest.importorskip("fastapi")


def _failing_box(tmp_path, monkeypatch, fail_mode: str) -> ForensicBlackBox:
    """A filesystem store whose record writes fail from now on (full disk)."""
    box = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"), fail_mode=fail_mode)
    _no_space(monkeypatch)
    return box


def _chat(tmp_path, monkeypatch, fail_mode: str, *, stream: bool = False):
    from _gateway_stream import MockUpstream, chat_body, settings, through

    completion = (
        b'{"id": "c1", "object": "chat.completion", "model": "example-model", "choices": '
        b'[{"index": 0, "message": {"role": "assistant", "content": "fine"}, '
        b'"finish_reason": "stop"}]}'
    )
    upstream = MockUpstream([completion], content_type="application/json")
    box = _failing_box(tmp_path, monkeypatch, fail_mode)
    response = through(
        upstream,
        chat_body(stream=stream),
        settings(ADMINA_FORENSIC_FAIL_MODE=fail_mode),
        state={"forensic_box": box},
    )
    return response, upstream, box


@pytest.mark.parametrize("stream", [False, True])
def test_gateway_closed_mode_answers_503_without_forwarding(
    proxy_deps, tmp_path, monkeypatch, stream
):
    response, upstream, box = _chat(tmp_path, monkeypatch, "closed", stream=stream)
    assert response.status_code == 503
    assert response.json() == {
        "error": {
            "message": "The forensic record of the request could not be written.",
            "type": "server_error",
            "param": None,
            "code": "forensic_unavailable",
        }
    }
    assert upstream.requests == []
    assert "X-Admina-Record-Hash" not in response.headers
    assert box.record_count == 0


def test_gateway_open_mode_serves_the_request(proxy_deps, tmp_path, monkeypatch, caplog):
    with caplog.at_level(logging.ERROR, logger="admina.forensic_blackbox"):
        response, upstream, box = _chat(tmp_path, monkeypatch, "open")
    assert response.status_code == 200
    assert len(upstream.requests) == 1
    assert "X-Admina-Record-Hash" not in response.headers
    assert box.record_count == 0
    assert any("not written" in r.getMessage() for r in caplog.records)


def _mcp(monkeypatch, box: ForensicBlackBox):
    from test_proxy_forensic_would_action import _inject_state, _post_mcp

    from admina.proxy import main as proxy_main

    _inject_state(monkeypatch, box, mode="enforce")
    proxy_main.app.state.proxy.firewall = _NoInjection()
    response = _post_mcp()
    return response, proxy_main.app.state.proxy.http_client.post


class _NoInjection:
    def check(self, text: str) -> dict:
        return {"is_injection": False, "risk_level": "low"}


def test_mcp_closed_mode_answers_503_without_forwarding(proxy_deps, tmp_path, monkeypatch):
    box = _failing_box(tmp_path, monkeypatch, "closed")
    response, upstream_post = _mcp(monkeypatch, box)
    assert response.status_code == 503
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["error"]["message"] == "The forensic record of the request could not be written."
    upstream_post.assert_not_called()


def test_mcp_open_mode_serves_the_request(proxy_deps, tmp_path, monkeypatch):
    box = _failing_box(tmp_path, monkeypatch, "open")
    response, upstream_post = _mcp(monkeypatch, box)
    assert response.status_code == 200
    upstream_post.assert_called_once()
    assert "X-Admina-Forensic-Hash" not in response.headers


def _validate(box: ForensicBlackBox):
    import httpx
    from _gateway_stream import FakeLoopBreaker, FakePII
    from fastapi import FastAPI

    from admina.proxy.api.integration import create_integration_endpoints

    app = FastAPI()
    app.include_router(
        create_integration_endpoints(
            get_firewall=lambda: _NoInjection(),
            get_pii_scanner=lambda: FakePII(),
            get_loop_breaker=lambda: FakeLoopBreaker(),
            get_forensic_box=lambda: box,
        )
    )

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/api/v1/validate", json={"content": "hello"})

    return asyncio.run(go())


def test_validate_closed_mode_answers_503_while_records_fail(proxy_deps, tmp_path, monkeypatch):
    box = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"), fail_mode="closed")
    assert _validate(box).status_code == 200
    with monkeypatch.context() as m:
        _no_space(m)
        with pytest.raises(ForensicWriteError):
            box.record({"event_id": "e1"})
    response = _validate(box)
    assert response.status_code == 503
    assert "forensic" in response.json()["detail"].lower()
    box.record({"event_id": "e2"})
    assert _validate(box).status_code == 200


def test_validate_open_mode_is_served_while_records_fail(proxy_deps, tmp_path, monkeypatch):
    box = _failing_box(tmp_path, monkeypatch, "open")
    box.record({"event_id": "e1"})
    assert _validate(box).status_code == 200


def _health(monkeypatch, box) -> dict:
    from test_health_fields import _health as health

    return health(monkeypatch, box)


@root_only
def test_health_is_degraded_on_a_read_only_directory(proxy_deps, tmp_path, monkeypatch):
    directory = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(directory))
    directory.chmod(0o500)
    try:
        body = _health(monkeypatch, box)
    finally:
        directory.chmod(0o700)
    assert body["forensic_writable"] is False
    assert body["status"] == "degraded"


def test_health_is_degraded_after_a_failed_record(proxy_deps, tmp_path, monkeypatch):
    box = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"))
    with monkeypatch.context() as m:
        _no_space(m)
        box.record({"event_id": "e1"})
    assert _health(monkeypatch, box)["status"] == "degraded"
    box.record({"event_id": "e2"})
    assert _health(monkeypatch, box)["status"] == "healthy"


# ── Proxy startup ─────────────────────────────────────────────


def _start(monkeypatch, fail_mode: str, backend: str, directory: str = ""):
    """Run the proxy lifespan; return (state, /health body)."""
    from _proxy_app import isolate, serve

    from admina.proxy import main as proxy_main

    isolate(monkeypatch, forensic_backend=backend, forensic_dir=directory)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_FORENSIC_FAIL_MODE", fail_mode)
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    responses, state = serve(
        [
            {"method": "GET", "url": "/health"},
            {
                "method": "POST",
                "url": "/v1/chat/completions",
                "json": {"model": "m1", "messages": [{"role": "user", "content": "hello"}]},
            },
        ]
    )
    return state, responses[0].json(), responses[1]


def _start_fails(monkeypatch, backend: str, directory: str = "") -> str:
    from _proxy_app import isolate
    from fastapi import FastAPI

    from admina.proxy import main as proxy_main
    from admina.proxy.forensic_backend import ForensicBackendError

    isolate(monkeypatch, forensic_backend=backend, forensic_dir=directory)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_FORENSIC_FAIL_MODE", "closed")

    async def go():
        async with proxy_main.lifespan(FastAPI()):
            pass

    with pytest.raises(ForensicBackendError) as excinfo:
        asyncio.run(go())
    return str(excinfo.value)


def _assert_unavailable(state, health: dict, chat) -> None:
    from admina.domains.compliance.forensic import UnavailableForensicStore

    assert isinstance(state.forensic_box, UnavailableForensicStore)
    assert health["forensic_writable"] is False
    assert health["status"] == "degraded"
    # Served, with nothing recorded anywhere (not even in memory).
    assert chat.status_code == 200
    assert state.forensic_box.record_count == 0
    assert "X-Admina-Record-Hash" not in chat.headers


def test_filesystem_without_a_directory_stops_the_proxy_in_closed_mode(proxy_deps, monkeypatch):
    assert "FORENSIC_BASE_DIR" in _start_fails(monkeypatch, "filesystem", "")


def test_filesystem_without_a_directory_in_open_mode(proxy_deps, monkeypatch, caplog):
    with caplog.at_level(logging.ERROR):
        state, health, chat = _start(monkeypatch, "open", "filesystem", "")
    _assert_unavailable(state, health, chat)
    assert any(
        "FORENSIC_BASE_DIR" in r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR
    )


@root_only
def test_a_directory_that_cannot_be_created(proxy_deps, tmp_path, monkeypatch, caplog):
    parent = tmp_path / "locked"
    parent.mkdir()
    parent.chmod(0o500)
    try:
        assert "forensic" in _start_fails(monkeypatch, "filesystem", str(parent / "f")).lower()
        with caplog.at_level(logging.ERROR):
            state, health, chat = _start(monkeypatch, "open", "filesystem", str(parent / "f"))
    finally:
        parent.chmod(0o700)
    _assert_unavailable(state, health, chat)


@root_only
def test_a_read_only_directory_stops_the_proxy_in_closed_mode(proxy_deps, tmp_path, monkeypatch):
    directory = tmp_path / "forensic"
    directory.mkdir()
    directory.chmod(0o500)
    try:
        assert "not writable" in _start_fails(monkeypatch, "filesystem", str(directory))
    finally:
        directory.chmod(0o700)


class _UnreachableS3:
    def list_buckets(self):
        raise ConnectionError("endpoint not reachable")


def _fake_boto3(monkeypatch, client) -> None:
    import sys
    import types

    module = types.ModuleType("boto3")
    module.client = lambda **_kw: client
    monkeypatch.setitem(sys.modules, "boto3", module)


def test_s3_not_reachable_stops_the_proxy_in_closed_mode(proxy_deps, monkeypatch):
    _fake_boto3(monkeypatch, _UnreachableS3())
    assert "S3" in _start_fails(monkeypatch, "s3")


def test_s3_not_reachable_in_open_mode(proxy_deps, monkeypatch, caplog):
    _fake_boto3(monkeypatch, _UnreachableS3())
    with caplog.at_level(logging.ERROR):
        state, health, chat = _start(monkeypatch, "open", "s3")
    _assert_unavailable(state, health, chat)


def test_s3_without_boto3_stops_the_proxy_in_closed_mode(proxy_deps, monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "boto3", None)
    assert "boto3" in _start_fails(monkeypatch, "s3")


def _bucket_with_an_unreadable_record(monkeypatch, case: str) -> MemoryBucket:
    """A bucket with two records, one of which cannot be read: the last one
    of a valid chain state (``head``), or the first one when the chain state
    is missing and the key would rebuild it (``rebuild``)."""
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "FORENSIC_S3_MAX_RETRIES", 1)
    monkeypatch.setattr(proxy_main.settings, "FORENSIC_S3_BASE_DELAY_S", 0.0)
    for name in ("ADMINA_FORENSIC_STATE_KEY", "ADMINA_FORENSIC_STATE_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    key = None
    if case == "rebuild":
        key = "canary-" + secrets.token_hex(16)
        monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY", key)
    bucket = MemoryBucket()
    box = ForensicBlackBox(boto3_client=bucket, bucket="b", state_signing_key=key)
    box.record({"event_id": "e1"})
    box.record({"event_id": "e2"})
    if case == "rebuild":
        del bucket.objects[STATE]
        bucket.fail("/00000001.json", 100)
    else:
        bucket.fail("/00000002.json", 100)
    return bucket


@pytest.mark.parametrize("case", ["head", "rebuild"])
def test_an_s3_record_that_cannot_be_read_stops_the_proxy_in_closed_mode(
    proxy_deps, monkeypatch, case
):
    _fake_boto3(monkeypatch, _bucket_with_an_unreadable_record(monkeypatch, case))
    assert "cannot be used" in _start_fails(monkeypatch, "s3")


@pytest.mark.parametrize("case", ["head", "rebuild"])
def test_an_s3_record_that_cannot_be_read_in_open_mode(proxy_deps, monkeypatch, caplog, case):
    _fake_boto3(monkeypatch, _bucket_with_an_unreadable_record(monkeypatch, case))
    with caplog.at_level(logging.ERROR):
        state, health, chat = _start(monkeypatch, "open", "s3")
    _assert_unavailable(state, health, chat)
    assert any("cannot be used" in r.getMessage() for r in caplog.records)


def test_an_s3_chain_state_that_cannot_be_written_at_startup_stops_the_proxy_in_closed_mode(
    proxy_deps, monkeypatch
):
    bucket = _bucket_with_an_unreadable_record(monkeypatch, "rebuild")
    bucket.fail("/00000001.json", 0)

    def put_object(**_kw):
        raise S3Error("SlowDown", 503)

    bucket.put_object = put_object
    _fake_boto3(monkeypatch, bucket)
    assert "cannot be used" in _start_fails(monkeypatch, "s3")


def test_a_working_directory_in_closed_mode(proxy_deps, tmp_path, monkeypatch):
    state, health, chat = _start(monkeypatch, "closed", "filesystem", str(tmp_path / "forensic"))
    assert state.forensic_box.fail_mode == "closed"
    assert health["forensic_writable"] is True
    assert health["status"] == "healthy"
    assert chat.status_code == 200
    assert state.forensic_box.record_count == 2


def _audit(box: ForensicBlackBox):
    import httpx
    from fastapi import FastAPI

    from admina.proxy.api.integration import create_integration_endpoints

    app = FastAPI()
    app.include_router(
        create_integration_endpoints(
            get_firewall=lambda: None,
            get_pii_scanner=lambda: None,
            get_loop_breaker=lambda: None,
            get_forensic_box=lambda: box,
        )
    )

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/api/v1/audit", json={"event": {"action": "done"}})

    return asyncio.run(go())


def test_audit_closed_mode_answers_503(proxy_deps, tmp_path, monkeypatch):
    response = _audit(_failing_box(tmp_path, monkeypatch, "closed"))
    assert response.status_code == 503


def test_audit_open_mode_reports_the_record_as_not_written(proxy_deps, tmp_path, monkeypatch):
    response = _audit(_failing_box(tmp_path, monkeypatch, "open"))
    assert response.status_code == 200
    assert response.json() == {
        "recorded": False,
        "error": "The forensic record could not be written",
    }


# ── A keyed store started without its key ─────────────────────
#
# A store whose chain was written with ADMINA_FORENSIC_STATE_KEY keeps the
# signature of its chain state (_chain_state.json.sig) beside it. Started
# without the key, it would write unsigned records, which a keyed
# verification reports as "unsigned": in closed mode the store does not
# start (ForensicKeyError), in open mode it starts with a WARNING, at every
# start until the key is set again or the store is moved aside.


def _keyless(monkeypatch) -> None:
    monkeypatch.delenv("ADMINA_FORENSIC_STATE_KEY", raising=False)
    monkeypatch.delenv("ADMINA_FORENSIC_STATE_KEY_FILE", raising=False)


def _keyed_store(directory) -> None:
    box = ForensicBlackBox(filesystem_dir=str(directory), state_signing_key=secrets.token_hex(16))
    box.record({"event_id": "e1"})
    box.record({"event_id": "e2"})


def test_a_keyed_store_without_its_key_does_not_start_in_closed_mode(tmp_path, monkeypatch):
    from admina.domains.compliance.forensic import ForensicKeyError

    _keyless(monkeypatch)
    _keyed_store(tmp_path)
    with pytest.raises(ForensicKeyError, match="ADMINA_FORENSIC_STATE_KEY"):
        ForensicBlackBox(filesystem_dir=str(tmp_path), fail_mode="closed")
    assert len(record_files(tmp_path)) == 2


def test_a_keyed_store_without_its_key_warns_in_open_mode(tmp_path, monkeypatch, caplog):
    _keyless(monkeypatch)
    _keyed_store(tmp_path)
    for _ in range(2):  # at every start, also after an unsigned record
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="admina.forensic_blackbox"):
            box = ForensicBlackBox(filesystem_dir=str(tmp_path))
        warnings = [r for r in caplog.records if "ADMINA_FORENSIC_STATE_KEY" in r.getMessage()]
        assert [r.levelno for r in warnings] == [logging.WARNING]
        assert box.record({"event_id": "e3"})["stored"] is True


def test_a_store_never_keyed_starts_without_a_key_in_closed_mode(tmp_path, monkeypatch, caplog):
    _keyless(monkeypatch)
    ForensicBlackBox(filesystem_dir=str(tmp_path)).record({"event_id": "e1"})
    with caplog.at_level(logging.WARNING, logger="admina.forensic_blackbox"):
        box = ForensicBlackBox(filesystem_dir=str(tmp_path), fail_mode="closed")
    assert box.chain_status == "ok"
    assert not [r for r in caplog.records if "ADMINA_FORENSIC_STATE_KEY" in r.getMessage()]


def test_a_keyed_store_with_its_key_starts_in_closed_mode(tmp_path, monkeypatch, caplog):
    _keyless(monkeypatch)
    key = secrets.token_hex(16)
    ForensicBlackBox(filesystem_dir=str(tmp_path), state_signing_key=key).record({"e": 1})
    with caplog.at_level(logging.WARNING, logger="admina.forensic_blackbox"):
        box = ForensicBlackBox(
            filesystem_dir=str(tmp_path), state_signing_key=key, fail_mode="closed"
        )
    assert box.chain_status == "ok"
    assert not [r for r in caplog.records if "ADMINA_FORENSIC_STATE_KEY" in r.getMessage()]


def test_a_keyed_s3_store_without_its_key_does_not_start_in_closed_mode(monkeypatch):
    from admina.domains.compliance.forensic import ForensicKeyError

    _keyless(monkeypatch)
    bucket = MemoryBucket()
    keyed = ForensicBlackBox(boto3_client=bucket, state_signing_key=secrets.token_hex(16))
    keyed.record({"event_id": "e1"})
    with pytest.raises(ForensicKeyError):
        ForensicBlackBox(boto3_client=bucket, fail_mode="closed")


def test_a_keyed_store_without_its_key_stops_the_proxy_in_closed_mode(
    proxy_deps, tmp_path, monkeypatch
):
    _keyless(monkeypatch)
    _keyed_store(tmp_path / "forensic")
    message = _start_fails(monkeypatch, "filesystem", str(tmp_path / "forensic"))
    assert "ADMINA_FORENSIC_STATE_KEY" in message


def test_a_keyed_store_without_its_key_starts_the_proxy_in_open_mode(
    proxy_deps, tmp_path, monkeypatch, caplog
):
    _keyless(monkeypatch)
    _keyed_store(tmp_path / "forensic")
    with caplog.at_level(logging.WARNING):
        state, health, chat = _start(monkeypatch, "open", "filesystem", str(tmp_path / "forensic"))
    assert chat.status_code == 200
    assert state.forensic_box.record_count > 2
    assert any(
        r.levelno == logging.WARNING and "ADMINA_FORENSIC_STATE_KEY" in r.getMessage()
        for r in caplog.records
    )

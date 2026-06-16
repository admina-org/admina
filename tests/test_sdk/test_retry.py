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

"""Retry executor + policy."""

from __future__ import annotations

import asyncio

import pytest

from admina.sdk.errors import RetryableUpstreamError, TerminalUpstreamError
from admina.sdk.retry import RetryPolicy, run_with_retry


def test_no_retry_when_policy_none_single_attempt():
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        return "ok"

    out = asyncio.run(run_with_retry(factory, None))
    assert out == "ok" and calls["n"] == 1


def test_retries_transient_then_succeeds():
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RetryableUpstreamError("transient")
        return "ok"

    p = RetryPolicy(max_attempts=5, base_delay_s=0.0)  # 0 delay for fast test
    out = asyncio.run(run_with_retry(factory, p))
    assert out == "ok" and calls["n"] == 3


def test_does_not_retry_terminal():
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        raise PermissionError("residency violation")

    p = RetryPolicy(max_attempts=5, base_delay_s=0.0)
    with pytest.raises(PermissionError):
        asyncio.run(run_with_retry(factory, p))
    assert calls["n"] == 1  # default-deny: not retried


def test_exhaustion_raises_last_error():
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        raise RetryableUpstreamError("always")

    p = RetryPolicy(max_attempts=3, base_delay_s=0.0)
    with pytest.raises(RetryableUpstreamError):
        asyncio.run(run_with_retry(factory, p))
    assert calls["n"] == 3


def test_per_attempt_timeout():
    async def factory():
        await asyncio.sleep(10)  # exceeds timeout

    p = RetryPolicy(max_attempts=1, base_delay_s=0.0, timeout_s=0.05)
    with pytest.raises((asyncio.TimeoutError, TimeoutError)):
        asyncio.run(run_with_retry(factory, p))


def test_custom_classifier():
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        raise ValueError("retry me")

    p = RetryPolicy(max_attempts=3, base_delay_s=0.0, retry_on=lambda e: isinstance(e, ValueError))
    with pytest.raises(ValueError):
        asyncio.run(run_with_retry(factory, p))
    assert calls["n"] == 3  # custom classifier made ValueError retryable


def test_does_not_retry_terminal_marker():
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        raise TerminalUpstreamError("do not retry")

    p = RetryPolicy(max_attempts=5, base_delay_s=0.0)
    with pytest.raises(TerminalUpstreamError):
        asyncio.run(run_with_retry(factory, p))
    assert calls["n"] == 1


def test_invalid_max_attempts_rejected():
    with pytest.raises(ValueError, match="max_attempts"):
        RetryPolicy(max_attempts=0)

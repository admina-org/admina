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

"""Vendored retry/backoff executor for the governed SDK primitives.

No third-party dependency (tenacity is not a runtime dep). Default-deny
retryability: only transient transport errors are retried; governance
refusals and unknown errors are terminal.
"""

from __future__ import annotations

import asyncio
import os
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from admina.sdk.errors import RetryableUpstreamError, TerminalUpstreamError

# Exception type-NAME hints for common provider transient errors (httpx, openai,
# botocore) — matched by name so the SDK does not import those optional deps.
_TRANSIENT_NAMES = frozenset(
    {
        "TimeoutException",
        "ConnectTimeout",
        "ReadTimeout",
        "ConnectError",
        "APITimeoutError",
        "APIConnectionError",
        "RateLimitError",
        "InternalServerError",
        "ServiceUnavailableError",
        "ThrottlingException",
    }
)


def _default_retryable(exc: BaseException) -> bool:
    """Default-deny classifier: True only for clearly-transient transport errors."""
    if isinstance(exc, TerminalUpstreamError):
        return False
    if isinstance(exc, RetryableUpstreamError):
        return True
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError, ConnectionError)):
        return True
    # name-based hint for optional-dep provider errors (not imported)
    if type(exc).__name__ in _TRANSIENT_NAMES:
        return True
    # HTTP status hint (httpx/requests-style): retry 429 + 5xx
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if isinstance(status, int) and (status == 429 or 500 <= status < 600):
        return True
    return False  # default-deny: PermissionError, ValueError, etc. are terminal


@dataclass
class RetryPolicy:
    max_attempts: int = 3
    base_delay_s: float = 0.2
    max_delay_s: float = 10.0
    jitter: str = "full"  # "none" | "full" | "equal"
    timeout_s: float | None = None  # per-attempt timeout (asyncio.wait_for)
    retry_on: Callable[[BaseException], bool] | None = None

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")

    @classmethod
    def from_env(cls) -> RetryPolicy:
        """Build from ADMINA_RETRY_* env vars (sane defaults if unset)."""
        return cls(
            max_attempts=int(os.environ.get("ADMINA_RETRY_MAX_ATTEMPTS", "3")),
            base_delay_s=float(os.environ.get("ADMINA_RETRY_BASE_DELAY_S", "0.2")),
            max_delay_s=float(os.environ.get("ADMINA_RETRY_MAX_DELAY_S", "10.0")),
            jitter=os.environ.get("ADMINA_RETRY_JITTER", "full"),
        )

    def _delay(self, attempt: int) -> float:
        raw = min(self.max_delay_s, self.base_delay_s * (2 ** (attempt - 1)))
        if self.jitter == "full":
            return random.uniform(0, raw)  # noqa: S311 — backoff jitter, not crypto
        if self.jitter == "equal":
            return raw / 2 + random.uniform(0, raw / 2)  # noqa: S311
        return raw


async def run_with_retry(
    coro_factory: Callable[[], Awaitable[Any]],
    policy: RetryPolicy | None,
    classify: Callable[[BaseException], bool] | None = None,
) -> Any:
    """Run coro_factory() with retry/backoff per *policy*.

    coro_factory is a no-arg callable returning a FRESH awaitable each call (a
    coroutine cannot be re-awaited). policy=None → exactly one attempt.
    """
    if policy is None:
        return await coro_factory()
    is_retryable = policy.retry_on or classify or _default_retryable
    last_exc: BaseException | None = None
    for attempt in range(1, policy.max_attempts + 1):
        try:
            aw = coro_factory()
            if policy.timeout_s is not None:
                return await asyncio.wait_for(aw, timeout=policy.timeout_s)
            return await aw
        except BaseException as exc:  # noqa: BLE001 — re-raised below if terminal
            last_exc = exc
            if attempt >= policy.max_attempts or not is_retryable(exc):
                raise
            await asyncio.sleep(policy._delay(attempt))
    assert last_exc is not None
    raise last_exc

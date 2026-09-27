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

"""``forensic_writable`` of ``GET /health``: the forensic store's write check.

The check is the store's ``writable()`` (with the filesystem backend, a probe
file created, written, fsynced and removed). It runs on a daemon thread of
its own, never on the event loop or on the loop's default executor, where the
gateway writes its forensic records.

- It runs at most once every :data:`PROBE_INTERVAL_S` seconds: the result is
  reused until then, and the calls made while a check runs share it.
- A caller waits at most :data:`PROBE_TIMEOUT_S` seconds from the start of
  the check, then gets ``False``. The check goes on; its result, when it
  comes, is reused like any other. No other check starts meanwhile, so a
  stalled store holds one thread at most.
- A check that raises reports ``False``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from contextlib import suppress
from typing import Any

__all__ = ["PROBE_INTERVAL_S", "PROBE_THREAD_NAME", "PROBE_TIMEOUT_S", "ForensicWriteProbe"]

logger = logging.getLogger("admina.proxy")

#: Seconds a check result is reused.
PROBE_INTERVAL_S = 10.0
#: Seconds a caller waits for a running check before it reports ``False``.
PROBE_TIMEOUT_S = 1.0
#: Name of the thread that runs a check.
PROBE_THREAD_NAME = "admina-forensic-probe"


class ForensicWriteProbe:
    """Runs a forensic store's ``writable()`` off the event loop, at most once
    per ``interval`` seconds, and waits for it at most ``timeout`` seconds."""

    def __init__(
        self,
        *,
        interval: float = PROBE_INTERVAL_S,
        timeout: float = PROBE_TIMEOUT_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.interval = interval
        self.timeout = timeout
        self._clock = clock
        self._lock = threading.Lock()
        self._store: Any = None
        self._result: bool | None = None
        self._checked_at: float | None = None
        self._running: Future[bool | None] | None = None
        self._started_at = 0.0

    async def check(self, store: Any) -> bool | None:
        """The result of ``store.writable()``.

        ``None`` without a store or when the store has no ``writable()``;
        ``False`` when the check raises or does not finish in time.
        """
        writable = getattr(store, "writable", None)
        if writable is None:
            return None
        with self._lock:
            now = self._clock()
            if store is not self._store:
                self._store = store
                self._checked_at = None
                self._running = None
            if self._checked_at is not None and now - self._checked_at < self.interval:
                return self._result
            if self._running is None:
                self._running = self._start(writable)
                self._started_at = now
            running = self._running
            remaining = self.timeout - (now - self._started_at)
        if remaining <= 0:
            return False
        return await _wait(running, remaining)

    def _start(self, writable: Callable[[], Any]) -> Future[bool | None]:
        """Run *writable* on a new daemon thread; called with the lock held."""
        running: Future[bool | None] = Future()
        running.set_running_or_notify_cancel()

        def run() -> None:
            try:
                value = writable()
                result = None if value is None else bool(value)
            except Exception:  # noqa: BLE001 — a failing check reports "not writable"
                logger.warning("Forensic store write check failed", exc_info=True)
                result = False
            with self._lock:
                if self._running is running:
                    self._result = result
                    self._checked_at = self._clock()
                    self._running = None
            running.set_result(result)

        threading.Thread(target=run, name=PROBE_THREAD_NAME, daemon=True).start()
        return running


async def _wait(running: Future[bool | None], timeout: float) -> bool | None:
    """The result of *running*, or ``False`` after *timeout* seconds."""
    loop = asyncio.get_running_loop()
    waiter: asyncio.Future[bool | None] = loop.create_future()

    def resolve(done: Future[bool | None]) -> None:
        if not waiter.done():
            waiter.set_result(done.result())

    def wake(done: Future[bool | None]) -> None:
        # Runs on the check's thread; the loop may be closed by then.
        with suppress(RuntimeError):
            loop.call_soon_threadsafe(resolve, done)

    running.add_done_callback(wake)
    try:
        return await asyncio.wait_for(waiter, timeout)
    except TimeoutError:
        return False
